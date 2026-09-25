#include <algorithm>
#include <string>
#include <vector>

#include "harness.hpp"
#include "icf/model/policy.hpp"
#include "icf/store/mutation.hpp"
#include "icf/model/registry.hpp"
#include "icf/model/terms.hpp"
#include "model_builder.hpp"

using namespace icf;
using namespace icf::test;

ICF_TEST(model, registry_validation_and_digest_stability) {
  Rng rng(11);
  PairFixture fixture = make_authorized_pair(rng);
  authorize_pair(fixture, rng);
  ICF_EXPECT_OK(fixture.registry.validate());
  const Digest first = fixture.registry.digest();
  const Digest second = fixture.registry.digest();
  ICF_EXPECT_EQ(first, second);

  // Rebuilding the same model from a copy must produce the same digest.
  model::Registry copy = fixture.registry;
  ICF_EXPECT_EQ(first, copy.digest());

  // A material change must change the digest.
  copy.clusters()[fixture.source.cluster.id].generation = Generation(6);
  ICF_EXPECT_NE(first, copy.digest());
}

ICF_TEST(model, digest_ignores_audit_trail) {
  Rng rng(12);
  PairFixture fixture = make_authorized_pair(rng);
  const Digest before = fixture.registry.digest();
  model::AuditRecord record;
  record.sequence = Sequence(1);
  record.actor = "test";
  record.action = "note";
  record.subject = "subject";
  record.outcome = Outcome::Ok;
  record.detail = "detail";
  ICF_EXPECT_OK(fixture.registry.append_audit(record));
  ICF_EXPECT_EQ(before, fixture.registry.digest());
}

ICF_TEST(model, rejects_inconsistent_records) {
  model::ClusterRecord cluster;
  cluster.id = ClusterId::parse("c1").value();
  // A cluster record without an authority domain cannot be registered.
  ICF_EXPECT_OUTCOME(Outcome::Invalid, model::Registry{}.put_cluster(cluster));
  cluster.domain = AuthorityDomainId::parse("d1").value();
  ICF_EXPECT_OK(model::Registry{}.put_cluster(cluster));
  cluster.id = ClusterId{};
  ICF_EXPECT_OUTCOME(Outcome::Invalid, model::Registry{}.put_cluster(cluster));

  Rng rng(13);
  PairFixture fixture = make_authorized_pair(rng);
  model::EndpointRecord foreign = endpoint_for(ClusterId::parse("other").value(), "x", "/x", 10, PolicyGeneration(1));
  model::ClusterRecord with_foreign = fixture.source.cluster;
  with_foreign.endpoints.push_back(foreign);
  ICF_EXPECT_OUTCOME(Outcome::Invalid, fixture.registry.put_cluster(with_foreign));

  model::ClusterRecord duplicate = fixture.source.cluster;
  duplicate.endpoints.push_back(duplicate.endpoints.front());
  ICF_EXPECT_OUTCOME(Outcome::AlreadyExists, fixture.registry.put_cluster(duplicate));

  model::EndpointRecord over = fixture.source.cluster.endpoints.front();
  over.reserved = CapacityUnits(over.capacity.value() + 1);
  model::ClusterRecord inconsistent = fixture.source.cluster;
  inconsistent.endpoints.clear();
  inconsistent.endpoints.push_back(over);
  ICF_EXPECT_OUTCOME(Outcome::CapacityExceeded, fixture.registry.put_cluster(inconsistent));

  model::LinkRecord self_link = make_link("self", fixture.source.endpoint, fixture.source.endpoint);
  ICF_EXPECT_OUTCOME(Outcome::Invalid, fixture.registry.put_link(self_link));

  model::PathRecord empty_path = make_path("empty", fixture.source.endpoint, fixture.target.endpoint, {});
  ICF_EXPECT_OUTCOME(Outcome::Invalid, fixture.registry.put_path(empty_path));

  model::ContractRecord same_cluster;
  same_cluster.id = ContractId::random(rng);
  const AuthorityDomainId domain_one = AuthorityDomainId::parse("d1").value();
  same_cluster.parties[0] = model::PartyRef{fixture.source.cluster.id, fixture.source.endpoint, domain_one};
  same_cluster.parties[1] = model::PartyRef{fixture.source.cluster.id, fixture.source.endpoint, domain_one};
  ICF_EXPECT_OUTCOME(Outcome::Invalid, fixture.registry.put_contract(same_cluster));

  model::GrantRecord dangling;
  dangling.id = GrantId::random(rng);
  dangling.contract = ContractId::random(rng);
  ICF_EXPECT_OUTCOME(Outcome::Invalid, store::validate_mutation(fixture.registry,
                                                                store::Mutation{store::MutationKind::GrantPut,
                                                                                {}, {}, {}, {}, {}, dangling}));
}

ICF_TEST(model, path_state_is_derived_from_links) {
  Rng rng(14);
  PairFixture fixture = make_authorized_pair(rng);
  const model::PathRecord* path = fixture.registry.find_path(PathId::parse("path-ab").value());
  ICF_ASSERT_TRUE(path != nullptr);
  ICF_EXPECT_EQ(model::PathState::Up, path->state);
  ICF_EXPECT_EQ(1000ull, path->bottleneck.value());

  model::LinkRecord down = *fixture.registry.find_link(EdgeId::parse("edge-ab").value());
  down.state = model::LinkState::Down;
  ICF_EXPECT_OK(fixture.registry.put_link(down));
  fixture.registry.recompute_path_states();
  ICF_EXPECT_EQ(model::PathState::Down, fixture.registry.find_path(PathId::parse("path-ab").value())->state);

  down.state = model::LinkState::Degraded;
  ICF_EXPECT_OK(fixture.registry.put_link(down));
  fixture.registry.recompute_path_states();
  ICF_EXPECT_EQ(model::PathState::Degraded, fixture.registry.find_path(PathId::parse("path-ab").value())->state);

  down.state = model::LinkState::Unknown;
  ICF_EXPECT_OK(fixture.registry.put_link(down));
  fixture.registry.recompute_path_states();
  ICF_EXPECT_EQ(model::PathState::Unknown, fixture.registry.find_path(PathId::parse("path-ab").value())->state);

  // An unsupported link kind is reported as unsupported, never as healthy.
  down.kind = model::LinkKind::OpticalInterconnect;
  down.state = model::LinkState::Up;
  ICF_EXPECT_OK(fixture.registry.put_link(down));
  fixture.registry.recompute_path_states();
  const model::PathRecord* unsupported = fixture.registry.find_path(PathId::parse("path-ab").value());
  ICF_EXPECT_TRUE(unsupported->contains_unsupported_edge);
  ICF_EXPECT_EQ(model::PathState::Down, unsupported->state);
  ICF_EXPECT_FALSE(model::link_kind_supported(model::LinkKind::OpticalInterconnect));
  ICF_EXPECT_TRUE(model::link_kind_supported(model::LinkKind::LoopbackTcp));
}

ICF_TEST(model, canonical_round_trip_every_record) {
  Rng rng(15);
  PairFixture fixture = make_authorized_pair(rng);
  authorize_pair(fixture, rng);
  fixture.registry.put_reservation(model::ReservationRecord{
      ReservationId::random(rng),
      fixture.grant,
      fixture.source.endpoint,
      fixture.source.cluster.id,
      CapacityUnits(50),
      false,
      fixture.now,
      Timestamp{},
      Revision(1),
      model::Provenance{model::EvidenceSource::DerivedFromTopology, model::VerificationState::Verified,
                        fixture.now, Revision(1), SessionToken{}, Digest{}}});
  model::AuditRecord audit;
  audit.sequence = Sequence(1);
  audit.at = fixture.now;
  audit.actor = "tester";
  audit.action = "unit";
  audit.subject = "subject";
  audit.outcome = Outcome::Stale;
  audit.detail = "audit detail";
  ICF_EXPECT_OK(fixture.registry.append_audit(audit));

  ByteWriter writer;
  model::encode_registry(fixture.registry, writer, true);
  ByteReader reader(writer.data());
  Result<model::Registry> decoded = model::decode_registry(reader);
  ICF_ASSERT_TRUE(decoded.has_value());
  ICF_EXPECT_OK(reader.expect_end());
  ICF_EXPECT_EQ(fixture.registry.digest(), decoded.value().digest());
  ICF_EXPECT_EQ(fixture.registry.counts().contracts, decoded.value().counts().contracts);
  ICF_EXPECT_EQ(fixture.registry.counts().grants, decoded.value().counts().grants);
  ICF_EXPECT_EQ(fixture.registry.counts().audit, decoded.value().counts().audit);
  ICF_EXPECT_EQ(fixture.registry.audit().front().detail, decoded.value().audit().front().detail);

  // The audit trail is excluded from the authorization digest but present in the snapshot.
  ByteWriter state_only;
  model::encode_registry(fixture.registry, state_only, false);
  ICF_EXPECT_TRUE(state_only.size() < writer.size());
}

ICF_TEST(model, canonical_rejects_tampered_and_truncated_input) {
  Rng rng(16);
  PairFixture fixture = make_authorized_pair(rng);
  ByteWriter writer;
  model::encode_registry(fixture.registry, writer, true);
  const std::vector<std::byte> bytes = writer.data();

  for (std::size_t cut = 1; cut < bytes.size(); cut += 17) {
    ByteReader reader(std::span<const std::byte>(bytes.data(), bytes.size() - cut));
    Result<model::Registry> decoded = model::decode_registry(reader);
    ICF_EXPECT_FALSE(decoded.has_value());
  }
  std::vector<std::byte> tampered = bytes;
  tampered[10] = static_cast<std::byte>(std::to_integer<std::uint8_t>(tampered[10]) ^ 0xFFu);
  ByteReader reader(tampered);
  ICF_EXPECT_FALSE(model::decode_registry(reader).has_value());

  // An unsupported encoding version is INCOMPATIBLE, not a silent success.
  std::vector<std::byte> future = bytes;
  future[0] = std::byte{0x00};
  future[1] = std::byte{0x09};
  ByteReader future_reader(future);
  ICF_EXPECT_OUTCOME(Outcome::Incompatible, model::decode_registry(future_reader));
}

ICF_TEST(model, terms_validation_and_digest) {
  Rng rng(17);
  PairFixture fixture = make_authorized_pair(rng);
  model::ContractTerms terms;
  terms.parties[0] = model::PartyRef{fixture.source.cluster.id, fixture.source.endpoint, fixture.source.cluster.domain};
  terms.parties[1] = model::PartyRef{fixture.target.cluster.id, fixture.target.endpoint, fixture.target.cluster.domain};
  terms.capacity = CapacityUnits(100);
  terms.lease_duration = Duration::from_minutes(1);
  terms.incarnations = {fixture.source.cluster.incarnation, fixture.target.cluster.incarnation};
  terms.generations = {fixture.source.cluster.generation, fixture.target.cluster.generation};
  terms.policies = {fixture.source.cluster.policy_generation, fixture.target.cluster.policy_generation};
  terms.proposed_at = fixture.now;
  ICF_EXPECT_OK(terms.validate());
  const Digest digest = terms.digest();

  model::ContractTerms changed = terms;
  changed.capacity = CapacityUnits(101);
  ICF_EXPECT_NE(digest, changed.digest());

  model::ContractTerms single_domain = terms;
  single_domain.parties[1].domain = single_domain.parties[0].domain;
  ICF_EXPECT_OUTCOME(Outcome::Unsupported, single_domain.validate());

  model::ContractTerms no_endpoint = terms;
  no_endpoint.parties[0].endpoint = EndpointId{};
  ICF_EXPECT_OUTCOME(Outcome::Invalid, no_endpoint.validate());

  model::ContractTerms negative_lease = terms;
  negative_lease.lease_duration = Duration::from_seconds(-1);
  ICF_EXPECT_OUTCOME(Outcome::Invalid, negative_lease.validate());

  ByteWriter writer;
  model::encode_terms(terms, writer);
  ByteReader reader(writer.data());
  Result<model::ContractTerms> decoded = model::decode_terms(reader);
  ICF_ASSERT_TRUE(decoded.has_value());
  ICF_EXPECT_OK(reader.expect_end());
  ICF_EXPECT_EQ(digest, decoded.value().digest());
}

ICF_TEST(model, audit_sequence_is_contiguous_and_bounded) {
  Rng rng(18);
  PairFixture fixture = make_authorized_pair(rng);
  model::AuditRecord first;
  first.sequence = Sequence(5);
  first.actor = "a";
  first.action = "b";
  first.subject = "c";
  ICF_EXPECT_OK(fixture.registry.append_audit(first));
  model::AuditRecord second = first;
  second.sequence = Sequence(7);
  ICF_EXPECT_OUTCOME(Outcome::Invalid, fixture.registry.append_audit(second));
  second.sequence = Sequence(6);
  ICF_EXPECT_OK(fixture.registry.append_audit(second));
}

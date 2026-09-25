#include "icf/client/client.hpp"

#include "icf/core/limits.hpp"
#include "icf/net/poller.hpp"

namespace icf::client {

Client::~Client() { close(); }

Result<Client> Client::connect(const ClientOptions& options, const Clock& clock) {
  if (options.port == 0) {
    return invalid("a client requires a port");
  }
  Result<net::Socket> socket = net::Socket::connect(options.host, options.port, options.connect_deadline, clock);
  if (!socket) {
    return socket.status();
  }
  Client client;
  client.options_ = options;
  client.clock_ = &clock;
  client.socket_ = std::move(socket.value());
  // The key verifies inbound frames from the first byte; the handshake itself is sent unsigned
  // because the peer cannot know which key to verify it with before it has read the identity.
  client.verify_key_.assign(reinterpret_cast<const std::byte*>(options.channel_key.data()),
                            reinterpret_cast<const std::byte*>(options.channel_key.data()) + options.channel_key.size());
  if (options.send_hello) {
    const Status hello = [&client, &clock]() -> Status {
      wire::HelloMessage message;
      message.role = client.options_.role;
      message.cluster = client.options_.cluster;
      message.domain = client.options_.domain;
      message.incarnation = IncarnationId::from_uuid(Uuid::parse("11111111-2222-4333-8444-555555555555").value());
      message.generation = Generation(1);
      message.policy_generation = PolicyGeneration(1);
      message.agent_term = Term(1);
      message.protocol_min = limits::kProtocolVersionMin;
      message.protocol_max = limits::kProtocolVersionMax;
      message.capabilities = client.options_.role == wire::PeerRole::Agent ? wire::kCapabilityAll : 0u;
      message.started_at = clock.now();
      Result<std::vector<std::byte>> payload = wire::encode_message(message);
      if (!payload) {
        return payload.status();
      }
      return client.send_frame(wire::MessageType::Hello, payload.value());
    }();
    if (!hello) {
      return hello;
    }
    Result<wire::Frame> reply = client.receive_frame();
    if (!reply) {
      return reply.status();
    }
    if (reply.value().header.type != wire::MessageType::HelloAck) {
      std::string detail = std::string("the peer answered the handshake with ") +
                           wire::to_string(reply.value().header.type);
      if (reply.value().header.type == wire::MessageType::Error) {
        ByteReader error_reader(reply.value().payload);
        const Result<wire::ErrorMessage> error = wire::decode_error(error_reader);
        if (error) {
          detail += std::string(": ") + ::icf::to_string(error.value().outcome) + " (" + error.value().detail + ")";
        }
      }
      return Status::make(Outcome::Invalid, detail);
    }
    ByteReader reader(reply.value().payload);
    Result<wire::HelloAckMessage> ack = wire::decode_hello_ack(reader);
    if (!ack) {
      return ack.status();
    }
    const Status end = reader.expect_end();
    if (!end) {
      return end;
    }
    client.hello_ack_ = ack.value();
    // From here on every frame the client sends is signed, which is what the peer now requires.
    client.signing_ = !client.verify_key_.empty();
  }
  return client;
}

Status Client::send_frame(wire::MessageType type, std::span<const std::byte> payload) {
  if (!socket_.valid()) {
    return Status::make(Outcome::Unreachable, "the client is not connected");
  }
  const std::size_t total =
      wire::frame_wire_size(static_cast<std::uint32_t>(payload.size()), signing_ && !options_.channel_key.empty());
  std::vector<std::byte> encoded;
  encoded.reserve(total);
  wire::FrameHeader header;
  header.version = limits::kProtocolVersionMax;
  header.type = type;
  const bool sign = signing_ && !options_.channel_key.empty();
  header.flags = sign ? wire::kFlagSigned : 0u;
  const auto key = sign ? std::span<const std::byte>(reinterpret_cast<const std::byte*>(options_.channel_key.data()),
                                                     options_.channel_key.size())
                        : std::span<const std::byte>();
  const Status appended = wire::append_frame(encoded, header, payload, key);
  if (!appended) {
    return appended;
  }
  return send_raw(encoded);
}

Status Client::send_raw(std::span<const std::byte> bytes) {
  std::size_t offset = 0;
  const std::int64_t deadline = clock_->monotonic_nanos() + options_.reply_deadline.nanos();
  while (offset < bytes.size()) {
    Result<std::size_t> written = socket_.send(bytes.subspan(offset));
    if (!written) {
      if (written.status().outcome() != Outcome::Busy) {
        return written.status();
      }
      net::PollItem item;
      item.handle = socket_.handle();
      item.want_write = true;
      const Result<std::size_t> ready = net::poll_sockets(std::span<net::PollItem>(&item, 1), 250);
      if (!ready) {
        return ready.status();
      }
      if (clock_->monotonic_nanos() > deadline) {
        return Status::make(Outcome::Unreachable, "the send deadline expired");
      }
      continue;
    }
    offset += written.value();
  }
  return Status::ok();
}

Status Client::wait_readable(Duration deadline) const {
  const std::int64_t limit = clock_->monotonic_nanos() + deadline.nanos();
  for (;;) {
    net::PollItem item;
    item.handle = socket_.handle();
    item.want_read = true;
    const Result<std::size_t> ready = net::poll_sockets(std::span<net::PollItem>(&item, 1), 250);
    if (!ready) {
      return ready.status();
    }
    if (item.failed) {
      return Status::make(Outcome::Unreachable, "the peer closed the connection");
    }
    if (ready.value() > 0) {
      return Status::ok();
    }
    if (clock_->monotonic_nanos() > limit) {
      return Status::make(Outcome::Unreachable, "the reply deadline expired");
    }
  }
}

Result<wire::Frame> Client::receive_frame(Duration deadline) {
  const auto key = verify_key_.empty() ? std::span<const std::byte>() : std::span<const std::byte>(verify_key_);
  const std::int64_t limit = clock_->monotonic_nanos() + deadline.nanos();
  std::array<std::byte, 16 * 1024> buffer{};
  for (;;) {
    Result<std::optional<wire::Frame>> frame = parser_.next(key);
    if (!frame) {
      return frame.status();
    }
    if (frame.value().has_value()) {
      return std::move(frame.value().value());
    }
    const Status readable = wait_readable(Duration::from_millis(250));
    if (!readable) {
      return readable;
    }
    if (clock_->monotonic_nanos() > limit) {
      return Status::make(Outcome::Unreachable, "the reply deadline expired");
    }
    Result<std::size_t> received = socket_.receive(buffer);
    if (!received) {
      if (received.status().outcome() == Outcome::Busy) {
        continue;
      }
      return received.status();
    }
    if (received.value() == 0) {
      return Status::make(Outcome::Unreachable, "the peer closed the connection");
    }
    const Status pushed = parser_.push(std::span<const std::byte>(buffer.data(), received.value()));
    if (!pushed) {
      return pushed;
    }
  }
}

Result<wire::QueryResultMessage> Client::query(const wire::QueryMessage& request) {
  Result<std::vector<std::byte>> payload = wire::encode_message(request);
  if (!payload) {
    return payload.status();
  }
  const Status sent = send_frame(wire::MessageType::Query, payload.value());
  if (!sent) {
    return sent;
  }
  const std::int64_t limit = clock_->monotonic_nanos() + options_.reply_deadline.nanos();
  for (;;) {
    Result<wire::Frame> frame = receive_frame();
    if (!frame) {
      return frame.status();
    }
    if (frame.value().header.type == wire::MessageType::Ping) {
      wire::PongMessage pong;
      ByteReader ping_reader(frame.value().payload);
      Result<wire::PingMessage> ping = wire::decode_ping(ping_reader);
      if (ping) {
        pong.sequence = ping.value().sequence;
        Result<std::vector<std::byte>> pong_payload = wire::encode_message(pong);
        if (pong_payload) {
          (void)send_frame(wire::MessageType::Pong, pong_payload.value());
        }
      }
      continue;
    }
    if (frame.value().header.type != wire::MessageType::QueryResult) {
      return Status::make(Outcome::Invalid, "unexpected message while waiting for a query result");
    }
    ByteReader reader(frame.value().payload);
    Result<wire::QueryResultMessage> result = wire::decode_query_result(reader);
    if (!result) {
      return result.status();
    }
    const Status end = reader.expect_end();
    if (!end) {
      return end;
    }
    if (result.value().request != request.request) {
      if (clock_->monotonic_nanos() > limit) {
        return Status::make(Outcome::Indeterminate, "a reply for a different request arrived after the deadline");
      }
      continue;
    }
    return result.value();
  }
}

Result<wire::AdminResultMessage> Client::admin(const wire::AdminMessage& request) {
  Result<std::vector<std::byte>> payload = wire::encode_message(request);
  if (!payload) {
    return payload.status();
  }
  const Status sent = send_frame(wire::MessageType::Admin, payload.value());
  if (!sent) {
    return sent;
  }
  for (;;) {
    Result<wire::Frame> frame = receive_frame();
    if (!frame) {
      return frame.status();
    }
    if (frame.value().header.type == wire::MessageType::Ping) {
      continue;
    }
    if (frame.value().header.type != wire::MessageType::AdminResult) {
      return Status::make(Outcome::Invalid, "unexpected message while waiting for an administrative result");
    }
    ByteReader reader(frame.value().payload);
    Result<wire::AdminResultMessage> result = wire::decode_admin_result(reader);
    if (!result) {
      return result.status();
    }
    const Status end = reader.expect_end();
    if (!end) {
      return end;
    }
    if (result.value().request != request.request) {
      continue;
    }
    return result.value();
  }
}

Status Client::send_consent(const wire::ContractConsentMessage& consent) {
  Result<std::vector<std::byte>> payload = wire::encode_message(consent);
  if (!payload) {
    return payload.status();
  }
  return send_frame(wire::MessageType::ContractConsent, payload.value());
}

Status Client::send_withdraw(const wire::WithdrawMessage& withdraw) {
  Result<std::vector<std::byte>> payload = wire::encode_message(withdraw);
  if (!payload) {
    return payload.status();
  }
  return send_frame(wire::MessageType::Withdraw, payload.value());
}

}  // namespace icf::client

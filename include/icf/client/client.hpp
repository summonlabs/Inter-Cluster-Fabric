// Inter-Cluster Fabric - synchronous protocol client.
//
// Used by the CLI, the benchmarks, and the test suite. The client performs the handshake, keeps
// the session token, signs frames when a channel key is configured, and matches replies to
// requests by request identifier.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "icf/core/time.hpp"
#include "icf/net/socket.hpp"
#include "icf/wire/messages.hpp"

namespace icf::client {

struct ClientOptions {
  std::string host = "127.0.0.1";
  std::uint16_t port = 0;
  wire::PeerRole role = wire::PeerRole::Observer;
  ClusterId cluster;
  AuthorityDomainId domain;
  std::string channel_key;
  Duration connect_deadline = Duration::from_millis(limits::kDefaultConnectDeadlineMillis);
  Duration reply_deadline = Duration::from_seconds(10);
  bool send_hello = true;
};

class Client {
 public:
  Client() = default;
  ~Client();
  Client(Client&&) noexcept = default;
  Client& operator=(Client&&) noexcept = default;
  Client(const Client&) = delete;
  Client& operator=(const Client&) = delete;

  [[nodiscard]] static Result<Client> connect(const ClientOptions& options, const Clock& clock);

  [[nodiscard]] Status send_frame(wire::MessageType type, std::span<const std::byte> payload);
  [[nodiscard]] Result<wire::Frame> receive_frame(Duration deadline);
  [[nodiscard]] Result<wire::Frame> receive_frame() { return receive_frame(options_.reply_deadline); }

  [[nodiscard]] Status send_raw(std::span<const std::byte> bytes);

  [[nodiscard]] Result<wire::QueryResultMessage> query(const wire::QueryMessage& request);
  [[nodiscard]] Result<wire::AdminResultMessage> admin(const wire::AdminMessage& request);
  [[nodiscard]] Status send_consent(const wire::ContractConsentMessage& consent);
  [[nodiscard]] Status send_withdraw(const wire::WithdrawMessage& withdraw);

  [[nodiscard]] const wire::HelloAckMessage& hello_ack() const noexcept { return hello_ack_; }
  [[nodiscard]] const ClientOptions& options() const noexcept { return options_; }
  [[nodiscard]] bool connected() const noexcept { return socket_.valid(); }
  void close() noexcept { socket_.close(); }

 private:
  [[nodiscard]] Status wait_readable(Duration deadline) const;

  ClientOptions options_;
  const Clock* clock_ = nullptr;
  net::Socket socket_;
  wire::FrameParser parser_;
  wire::HelloAckMessage hello_ack_;
  std::vector<std::byte> verify_key_;
  bool signing_ = false;
};

}  // namespace icf::client

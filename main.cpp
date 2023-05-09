#include "boost/algorithm/string/replace.hpp"
#include "boost/locale/encoding_utf.hpp"
#include <boost/algorithm/string.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/core/stream_traits.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/http/message.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/beast/http/write.hpp>
#include <boost/beast/ssl/ssl_stream.hpp>
#include <boost/beast/version.hpp>
#include <boost/locale.hpp>
#include <boost/locale/generator.hpp>
#include <boost/system/detail/error_code.hpp>
#include <boost/url.hpp>
#include <boost/url/url.hpp>

#include "nlohmann/json_fwd.hpp"
#include <argh.h>
#include <clocale>
#include <cpp-base64/base64.cpp>
#include <cpp-base64/base64.h>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fmt/format.h>
#include <fmt/std.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <locale>
#include <memory>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <vector>

class tls_type {
 public:
  class utls_type {
    bool enabled{true};
    std::string fingerprint{"chrome"};
    friend void to_json(nlohmann::json &in_json, const utls_type &in_data) {
      in_json["enabled"]     = in_data.enabled;
      in_json["fingerprint"] = in_data.fingerprint;
    }
  };
  bool disable_sni;
  bool enabled{true};
  bool insecure{false};
  std::string server_name;
  utls_type utls;
  friend void to_json(nlohmann::json &in_json, const tls_type &in_data) {
    in_json["disable_sni"] = in_data.disable_sni;
    in_json["enabled"]     = in_data.enabled;
    in_json["insecure"]    = in_data.insecure;
    in_json["utls"]        = in_data.utls;
    if (!in_data.server_name.empty()) in_json["server_name"] = in_data.server_name;
  }
};
class transport_type {
 public:
  std::string type;
  std::string path;
  std::string headers_host{};
  friend void to_json(nlohmann::json &in_json, const transport_type &in_data) {
    in_json["type"] = in_data.type;
    in_json["path"] = in_data.path;
    if (!in_data.headers_host.empty()) in_json["headers"]["Host"] = in_data.headers_host;
  }
};

class multiplex_type {
 public:
  bool enabled;
  std::string protocol{"h2mux"};
  std::int32_t max_connections{4};
  friend void to_json(nlohmann::json &in_json, const multiplex_type &in_data) {
    in_json["enabled"]         = in_data.enabled;
    in_json["protocol"]        = in_data.protocol;
    in_json["max_connections"] = in_data.max_connections;
  }
};
class out_json {
 public:
  std::int32_t alter_id;
  std::string server;
  std::int32_t server_port;
  std::string tag;
  std::string type;
  std::string uuid;
  std::shared_ptr<tls_type> tls;
  std::shared_ptr<transport_type> transport;
  multiplex_type multiplex;

  friend void to_json(nlohmann::json &in_json, const out_json &in_data) {
    in_json["alter_id"]    = in_data.alter_id;
    in_json["security"]    = "auto";
    in_json["server"]      = in_data.server;
    in_json["server_port"] = in_data.server_port;
    in_json["tag"]         = in_data.tag;
    in_json["type"]        = in_data.type;
    in_json["network"]     = "tcp";
    in_json["uuid"]        = in_data.uuid;
    if (in_data.tls) {
      in_json["tls"] = *in_data.tls;
    }
    if (in_data.transport) {
      in_json["transport"] = *in_data.transport;
    }
    if (in_data.multiplex.enabled) {
      in_json["multiplex"] = in_data.multiplex;
    }
  }
};

std::vector<out_json> get_config(const std::string &in_body) {
  std::vector<out_json> l_ret{};
  std::stringstream l_str_str{base64_decode(in_body)};
  for (std::string l_str; std::getline(l_str_str, l_str);) {
    std::vector<std::string> l_config_list{};
    auto l_point = l_str.find(':');
    auto l_sub   = l_str.substr(l_point + 3);
    boost::replace_all(l_sub, "\r", "");
    std::cout << fmt::format("{}", l_str) << std::endl;
    auto l_json = nlohmann::json::parse(base64_decode(l_sub));
    std::cout << fmt::format("{}", base64_decode(l_sub)) << std::endl;

    auto l_file_name = l_json["ps"].get<std::string>();
    boost::replace_all(l_file_name, " ", "");
    boost::replace_all(l_file_name, "\t", "");

    out_json l_out{};
    l_out.alter_id =
        l_json["aid"].is_string() ? std::stoi(l_json["aid"].get<std::string>()) : l_json["aid"].get<std::int32_t>();
    l_out.type = l_str.substr(0, l_point);
    l_out.tag  = l_file_name;
    l_out.uuid = l_json["id"].get<std::string>();
    l_out.server_port =
        l_json["port"].is_string() ? std::stoi(l_json["port"].get<std::string>()) : l_json["port"].get<std::int32_t>();
    l_out.server = l_json["add"].get<std::string>();
    if (l_json["net"].get<std::string>() == "ws") {
      l_out.transport               = std::make_shared<transport_type>();
      l_out.transport->path         = l_json["path"].get<std::string>();
      l_out.transport->type         = l_json["net"].get<std::string>();
      l_out.transport->headers_host = l_json["host"].get<std::string>();
    }
    if (!l_json["tls"].empty()) {
      l_out.tls              = std::make_shared<tls_type>();
      l_out.tls->server_name = l_json["host"];
    }
    // l_out.multiplex.enabled = true;
    l_ret.emplace_back(l_out);
  }
  return l_ret;
}

int main(int argc, char *argv[]) try {
  std::locale::global(boost::locale::generator{}("zh_CN.UTF-8"));
  std::setlocale(LC_ALL, "zh_CN.UTF-8");

  argh::parser cmdl{{"--config", "--subscribe", "--out"}};
  cmdl.parse(argc, argv);

  boost::asio::io_context l_io_context{};
  boost::asio::ssl::context l_ssl_context{boost::asio::ssl::context::tlsv12_client};
  auto l_json = nlohmann::json::parse(std::ifstream{cmdl("config").str()});

  l_ssl_context.set_default_verify_paths();
  auto &l_route_direct = l_json["route"]["rules"].emplace_back();
  l_route_direct["outbound"] = "direct";
  for (auto &&i : cmdl.params("subscribe")) {
    boost::urls::url l_subscribe{i.second};
    std::cout << fmt::format("订阅地址 {}", i.second) << std::endl;
    boost::asio::ip::tcp::resolver l_resolver{l_io_context};
    boost::beast::ssl_stream<boost::beast::tcp_stream> l_stream{l_io_context, l_ssl_context};
    if (!SSL_set_tlsext_host_name(l_stream.native_handle(), l_subscribe.host().data())) {
      boost::beast::error_code l_ec{static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category()};
      throw boost::beast::system_error{l_ec};
    }

    auto const l_re = l_resolver.resolve(l_subscribe.host(), l_subscribe.has_port() ? l_subscribe.port() : "443");
    boost::beast::get_lowest_layer(l_stream).connect(l_re);

    l_stream.handshake(boost::asio::ssl::stream_base::client);

    boost::beast::http::request<boost::beast::http::string_body> l_req{
        boost::beast::http::verb::get, l_subscribe.encoded_target(), 11};
    l_req.set(boost::beast::http::field::host, l_subscribe.host());
    l_req.set(boost::beast::http::field::user_agent, BOOST_BEAST_VERSION_STRING);

    boost::beast::http::write(l_stream, l_req);

    boost::beast::flat_buffer l_buffer{};
    boost::beast::http::response<boost::beast::http::string_body> l_res{};
    boost::beast::http::read(l_stream, l_buffer, l_res);
    auto l_config = get_config(l_res.body());

    for (auto &&i : l_config) {
      l_json["outbounds"].push_back(i);
      l_json["outbounds"].front()["outbounds"].emplace_back(i.tag);
      l_route_direct["domain"].emplace_back(i.server);
    }
    boost::system::error_code l_ec{};
    l_stream.shutdown(l_ec);
    if (l_ec) std::cout << fmt::format("{}", l_ec.what()) << std::endl;
  }
  std::ofstream{cmdl("out").str()} << l_json.dump(2) << std::endl;
  return 0;
} catch (std::exception &e) {
  std::cout << fmt::format("{}", e.what()) << std::endl;
  return 0;
}

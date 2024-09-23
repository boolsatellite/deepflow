use std::{fmt, str};

use anyhow::Ok;
use clap::App;
use futures::future::ok;
use serde::{Deserialize, Serialize, Serializer};
use wasmtime_wasi::preview2::command;

use super::{
    super::{value_is_default, AppProtoHead, L7ResponseStatus, LogMessageType},
    ObfuscateCache, PostgreInfo,
};

use crate::{
    common::{
        enums::IpProtocol,
        flow::{L7PerfStats, L7Protocol, PacketDirection},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, ParseParam},
        meta_packet::EbpfFlags,
    },
    config::handler::LogParserConfig,
    flow_generator::{
        error::{Error, Result},
        protocol_logs::{
            pb_adapter::{L7ProtocolSendLog, L7Request, L7Response},
            set_captured_byte,
        },
    },
};

/// 存储命令共有6个，分别是“set”、“add”、“replace”、“append”、"prepend" 和 "cas"
/// 客户端发送：command key [flags] [exptime] length [noreply]
/// cas 较为特殊: cas key [flags] [exptime] length [casunique] [noreply]
///
///
const STORAGE_COMMANDS: [&str; 6] = ["set", "add", "replace", "append", "prepend", "cas"]; // 存储命令
const STORAGE_COMMANDS_RET: [&str; 4] = ["STORED", "NOT_STORED", "EXISTS", "NOT_FOUND"];
const RETRIEVAL_COMMANDS: [&str; 4] = ["get", "gets", "gat", "gats"];
// Each command sent by a client may be answered with an error string
const ERROR_STRING: [&str; 3] = ["ERROR", "CLIENT_ERROR", "SERVER_ERROR "];
const DELETE_COMMAND_RET: [&str; 2] = ["DELETED", "NOT_FOUND"];

#[derive(Serialize, Debug, Default, Clone)]
pub struct MemcachedInfo {
    pub msg_type: LogMessageType,

    // 存储命令:
    // command key [flags] [exptime] length [noreply]
    // cas key [flags] [exptime] length [casunique] [noreply]
    // 检索命令:
    // get <key>*\r\n
    // gets <key>*\r\n    more key strings separated by whitespace.
    // 删除命令:
    // delete <key> [noreply]\r\n
    pub command: String,
    // length limit of a key is set at 250 characters
    pub req_key: String,
    //in memcached 1.2.1 and higher, flags may be 32-bits,
    //insteadof 16, but you might want to restrict yourself
    //to 16 bits for compatibility with older versions.
    pub req_flags: u16,
    pub exptime: String,
    //not including the delimiting \r\n
    pub req_value_length: String,
    pub req_cas_unique: u64,
    //  optional parameter
    pub noreply: String,
    pub req_data_block: String,

    /*  VALUE <key> <flags> <bytes> [<cas unique>]\r\n
    <data block>\r\n                            */
    pub resp_data_length: String,
    pub resp_flags: u16,
    pub resp_cas_unique: String,

    // total infomation in one message resquest or response
    pub request: String,
    pub response: String,
    pub request_type: String,
    pub error: String,
    pub resp_status: L7ResponseStatus,

    flag: u8, // TODO: 未知作用
    rrt: u64,
}

impl L7ProtocolInfoInterface for MemcachedInfo {
    fn session_id(&self) -> Option<u32> {
        None
    }

    fn merge_log(&mut self, other: &mut L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::MemCachedInfo(other) = other {
            return self.merge(other);
        }
        core::result::Result::Ok(())
        //flow_generator::error::Error
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::MemCached,
            msg_type: self.msg_type,
            rrt: self.rrt,
        })
    }

    fn is_tls(&self) -> bool {
        false
    }
}

impl MemcachedInfo {
    fn merge(&mut self, other: &mut Self) -> Result<()> {
        self.response = other.response.clone();
        self.resp_cas_unique = other.resp_cas_unique.clone();
        self.resp_data_length = other.resp_data_length.clone();
        self.resp_status = other.resp_status.clone();
        self.error = other.error.clone();
        self.resp_flags = other.resp_flags.clone();
        self.resp_data_length = other.resp_data_length.clone();

        core::result::Result::Ok(())
    }
}

impl fmt::Display for MemcachedInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "resquest: {:?}", &self.request);
        write!(f, "response: {:?}", &self.response)
    }
}

impl From<MemcachedInfo> for L7ProtocolSendLog {
    fn from(f: MemcachedInfo) -> Self {
        let flags = if f.is_tls() {
            EbpfFlags::TLS.bits()
        } else {
            EbpfFlags::NONE.bits()
        };
        let log = L7ProtocolSendLog {
            captured_request_byte: f.request.len() as u32,
            captured_response_byte: f.response.len() as u32,
            req: L7Request {
                req_type: f.request_type.clone(),
                resource: f.req_key.clone(),
                ..Default::default()
            },
            resp: L7Response {
                result: f.response,
                status: f.resp_status,
                exception: f.error.clone(),
                ..Default::default()
            },
            version: None,
            ..Default::default()
        };
        return log;
    }
}

#[derive(Serialize, Default)]
pub struct MemCachedLog {
    info: MemcachedInfo,
    #[serde(skip)]
    // 用于记录指标数据，后面会说明如何计算
    perf_stats: Option<L7PerfStats>,
    #[serde(skip)]
    parsed: bool,
}

impl L7ProtocolParserInterface for MemCachedLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        if param.l4_protocol != IpProtocol::TCP {
            return false;
        }
        if param.port_dst == 11211 || param.port_src == 11211 {
            return true;
        }
        false
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        print!("FixMe: {:?}", payload);

        core::result::Result::Ok(L7ParseResult::None)
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::MemCached
    }

    fn parsable_on_tcp(&self) -> bool {
        true
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }
}

// test log parse

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::rc::Rc;
    use std::{cell::RefCell, fs};

    use super::*;

    use crate::{
        common::{flow::PacketDirection, l7_protocol_log::L7PerfCache, MetaPacket},
        flow_generator::L7_RRT_CACHE_CAPACITY,
        utils::test::Capture,
    };

    const FILE_DIR: &str = "resources/test/flow_generator/memcached";

    fn run(name: &str) -> String {
        let pcap_file = Path::new(FILE_DIR).join(name);
        let log_cache = Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY)));
        let capture = Capture::load_pcap(pcap_file, None);
        let mut packets = capture.as_meta_packets();
        if packets.is_empty() {
            return "".to_string();
        }
        let mut output: String = String::new();
        let first_dst_port = packets[0].lookup_key.dst_port;
        let mut memcached = MemCachedLog::default();
        for packet in packets.iter_mut() {
            packet.lookup_key.direction = if packet.lookup_key.dst_port == first_dst_port {
                PacketDirection::ClientToServer
            } else {
                PacketDirection::ServerToClient
            };
            let payload = match packet.get_l4_payload() {
                Some(p) => p,
                None => continue,
            };
            print!("run function payload: {:?}", payload);

            let param = &mut ParseParam::new(
                packet as &MetaPacket,
                log_cache.clone(),
                Default::default(),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                Default::default(),
                true,
                true,
            );
            param.set_captured_byte(payload.len());

            let is_memcached = match packet.lookup_key.direction {
                PacketDirection::ClientToServer => memcached.check_payload(payload, param),
                PacketDirection::ServerToClient => memcached.check_payload(payload, param),
            };

            let info = if let core::result::Result::Ok(i) = memcached.parse_payload(payload, param)
            {
                match i.unwrap_single() {
                    L7ProtocolInfo::MemCachedInfo(r) => r,
                    _ => unreachable!(),
                }
            } else {
                MemcachedInfo::default()
            };
            output.push_str(&format!("{} is_memcached: {}\n", info, is_memcached));
        }
        output
    }

    #[test]
    fn check() {
        //let files = vec!["memcached.pcap"];
        println!("check function run ==");
        let output: String = run("memcached.pcap");
        print!("check function output :{:?}", output);
    }
}

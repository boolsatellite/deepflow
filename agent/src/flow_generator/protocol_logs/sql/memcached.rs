use std::{fmt, str};

use anyhow::Ok;
use clap::App;
use futures::future::ok;
use serde::{Serialize, Serializer};
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
    pub resq_key: String,
    //in memcached 1.2.1 and higher, flags may be 32-bits,
    //insteadof 16, but you might want to restrict yourself
    //to 16 bits for compatibility with older versions.
    pub resq_flags: u16,
    pub exptime: String,
    //not including the delimiting \r\n
    pub length: String,
    pub resq_cas_unique: u64,
    //  optional parameter
    pub noreply: String,
    pub resq_data_block: String,

    /*  VALUE <key> <flags> <bytes> [<cas unique>]\r\n
    <data block>\r\n                            */
    pub resp_key: String,
    pub resp_flags: u16,
    pub resp_data_len: String,
    pub resp_cas_unique: String,

    // total infomation in one message resquest or response
    pub request: String,
    pub response: String,
    pub request_type: String,
    pub error: String,

    flag: u8, // TODO: 未知作用
    rrt: u64,
}

impl L7ProtocolInfoInterface for MemcachedInfo {
    fn session_id(&self) -> Option<u32> {
        None
    }

    fn merge_log(&mut self, other: &mut L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::MemCachedInfo(other) = other {
            self.merge(other)?;
        }
        Ok(())
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
        // TODO: redis 中的merge 是覆盖，未理解
        ok(())
    }
}

impl fmt::Display for MemcachedInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "resquest: {:?}", self.resquest);
        write!(f, "response: {:?}", self.response)
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
            captured_request_byte: f.resquest.len() as u32,
            captured_response_byte: f.response.len(),
            req: L7Request {
                req_type: f.request_type.clone(),
                resource: f.request.clone(),
                ..Default::default()
            },
            resp: L7Response {
                status: f.resp_status,
                exception: f.error.clone(),
                ..Default::default()
            },
            flags: flags,
            ..Default::default()
        };
        return log;
    }
}

#[derive(Default)]
pub struct MemCachedLog {
    info: MemcachedInfo,
    // #[serde(skip)]

    // 用于记录指标数据，后面会说明如何计算
    perf_stats: Option<L7PerfStats>,
    #[serde(skip)]
    parsed: bool,
}

impl L7ProtocolParserInterface for MemCachedLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        todo!()
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        todo!()
    }

    fn protocol(&self) -> L7Protocol {
        todo!()
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        todo!()
    }
}

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

    #[test]
    fn check() {}
}
/*
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

            // let is_memcached = match packet.lookup_key.direction {
            //     PacketDirection::ClientToServer => memcached.check_payload(payload, param),
            //     PacketDirection::ServerToClient => stringifier::decode(payload, false).is_ok(),
            // };

            //     let info = if let Ok(i) = memcached.parse_payload(payload, param) {
            //         match i.unwrap_single() {
            //             L7ProtocolInfo::MemCachedInfo(r) => r,
            //             _ => unreachable!(),
            //         }
            //     } else {
            //         MemcachedInfo::default()
            //     };

            //     output.push_str(&format!("{} is_memcached: {}\n", info, is_memcached));
            // }
            output
        }

        #[test]
        fn check() {
            let files = vec![("memcached.pcap", "memcached.result")];

            for item in files.iter() {
                let expected = fs::read_to_string(&Path::new(FILE_DIR).join(item.1)).unwrap();
                let output = run(item.0);

                if output != expected {
                    let output_path = Path::new("actual.txt");
                    fs::write(&output_path, &output).unwrap();
                    assert!(
                        output == expected,
                        "output different from expected {}, written to {:?}",
                        item.1,
                        output_path
                    );
                }
            }
        }
    }
}
/*

#[test]
fn test_decode() {
    let testcases = vec![
        (("*-1\r\n", true), Some("")),
        (
            ("*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$7\r\nmyvalue\r\n", true),
            Some(""),
        ),
        (("$0\r\n\r\n", true), Some("")),
        (("$-1\r\n", true), Some("")),
        (("$9\r\n12345", false), Some("")),
        (("$9\r\n12345", true), None),
        (("-1\r\n", true), Some("-1")),
        // _\r\n
        (("_\r\n", true), Some("")),
        (("_\r", true), None),
        // #<t|f>\r\n
        (("#t\r\n", true), Some("")),
        (("#t\r", true), None),
        // ,[<+|->]<integral>[.<fractional>][<E|e>[sign]<exponent>]\r\n
        // ,inf\r\n
        // ,-inf\r\n
        // ,nan\r\n
        ((",1.12\r\n", true), Some("")),
        // ([+|-]<number>\r\n
        (("(1112111211121112\r\n", true), Some("")),
        // !<length>\r\n<error>\r\n
        (("!9\r\nabcdefghi\r\n", true), Some("!abcdefghi")),
        // =<length>\r\n<encoding>:<data>\r\n
        (("=9\r\ntxt:abcde\r\n", true), Some("")),
        // %<number-of-entries>\r\n<key-1><value-1>...<key-n><value-n>
        (("%1\r\n+key\r\n:123\r\n", true), Some("")),
        // ~<number-of-elements>\r\n<element-1>...<element-n>
        // ><number-of-elements>\r\n<element-1>...<element-n>
        (("~2\r\n+key\r\n:123\r\n", true), Some("")),
    ];
    for (input, expected) in testcases.iter() {
        let output = stringifier::decode(&input.0.as_bytes(), input.1);
        assert_eq!(
            output.ok().as_ref().and_then(|vs| str::from_utf8(vs).ok()),
            *expected,
            "testcase input '{}' failed",
            str::from_utf8(input.0.as_bytes()).unwrap().escape_default()
        );
    }
}

#[test]
fn truncated_compound_type() {
    assert!(stringifier::decode(b"%1\r\n+key\r\n", false).is_ok());
    assert!(stringifier::decode(b"%1\r\n+key\r\n", true).is_err());
    let s = "*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$7\r\nmyvalue\r\n";
    for i in 0..(s.len() - 1) {
        assert!(stringifier::decode(&s.as_bytes()[..i], true).is_err());
    }
}

#[test]
fn check_perf() {
    let expected = vec![
        (
            "redis.pcap",
            L7PerfStats {
                request_count: 10,
                response_count: 10,
                err_client_count: 0,
                err_server_count: 0,
                err_timeout: 0,
                rrt_count: 10,
                rrt_sum: 592,
                rrt_max: 96,
                ..Default::default()
            },
        ),
        (
            "redis-error.pcap",
            L7PerfStats {
                request_count: 1,
                response_count: 1,
                err_client_count: 0,
                err_server_count: 1,
                err_timeout: 0,
                rrt_count: 1,
                rrt_sum: 73,
                rrt_max: 73,
                ..Default::default()
            },
        ),
        (
            "redis-debug.pcap",
            L7PerfStats {
                request_count: 1,
                response_count: 1,
                err_client_count: 0,
                err_server_count: 0,
                err_timeout: 0,
                rrt_count: 1,
                rrt_sum: 1209,
                rrt_max: 1209,
                ..Default::default()
            },
        ),
    ];

    for item in expected.iter() {
        assert_eq!(item.1, run_perf(item.0), "parse pcap {} unexcepted", item.0);
    }
}
fn run_perf(pcap: &str) -> L7PerfStats {
    let rrt_cache = Rc::new(RefCell::new(L7PerfCache::new(100)));
    let mut redis = RedisLog::default();

    let capture = Capture::load_pcap(Path::new(FILE_DIR).join(pcap), None);
    let mut packets = capture.as_meta_packets();
    if packets.len() < 2 {
        unreachable!();
    }

    let first_dst_port = packets[0].lookup_key.dst_port;
    for packet in packets.iter_mut() {
        if packet.lookup_key.dst_port == first_dst_port {
            packet.lookup_key.direction = PacketDirection::ClientToServer;
        } else {
            packet.lookup_key.direction = PacketDirection::ServerToClient;
        }
        if packet.get_l4_payload().is_some() {
            let _ = redis.parse_payload(
                packet.get_l4_payload().unwrap(),
                &ParseParam::new(
                    &*packet,
                    rrt_cache.clone(),
                    Default::default(),
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    Default::default(),
                    true,
                    true,
                ),
            );
        }
    }
    redis.perf_stats.unwrap()
}

fn encode_redis_command(command: &str) -> Vec<u8> {
    let n = command.split(" ").count();
    let mut output = Vec::from(format!("*{}\r\n", n));

    for arg in command.split(" ") {
        output.extend_from_slice(format!("${}\r\n{}\r\n", arg.len(), arg).as_bytes());
    }

    output
}

#[test]
fn check_obfuscation() {
    let testcases = [
            ("GET key ", "GET key"),
            ("AUTH", "AUTH"),
            ("AUTH my-secret-password", "AUTH ?"),
            ("AUTH james my-secret-password", "AUTH ?"),
            ("HELLO 3 AUTH username passwd SETNAME cliname", "HELLO 3 AUTH ?"),
            ("APPEND key value", "APPEND key ?"),
            ("GETSET key value", "GETSET key ?"),
            ("LPUSHX key value", "LPUSHX key ?"),
            ("GEORADIUSBYMEMBER Sicily Agrigento 100 km", "GEORADIUSBYMEMBER Sicily ? 100 km"),
            ("RPUSHX key value", "RPUSHX key ?"),
            ("SET key value", "SET key ?"),
            ("SET anotherkey value EX 60", "SET anotherkey ? EX 60"),
            ("SETNX key value", "SETNX key ?"),
            ("SISMEMBER key member", "SISMEMBER key ?"),
            ("ZRANK key member", "ZRANK key ?"),
            ("ZREVRANK key member", "ZREVRANK key ?"),
            ("ZSCORE key member", "ZSCORE key ?"),
            ("BITFIELD key GET type offset SET type offset value INCRBY type", "BITFIELD key GET type offset SET type offset ? INCRBY type"),
            ("BITFIELD key SET type offset value INCRBY type", "BITFIELD key SET type offset ? INCRBY type"),
            ("BITFIELD key GET type offset INCRBY type", "BITFIELD key GET type offset INCRBY type"),
            ("BITFIELD key SET type offset", "BITFIELD key SET type offset"),
            ("CONFIG SET parameter value", "CONFIG SET parameter ?"),
            ("CONFIG foo bar baz", "CONFIG foo bar baz"),
            ("GEOADD key longitude latitude member longitude latitude member longitude latitude member", "GEOADD key longitude latitude ? longitude latitude ? longitude latitude ?"),
            ("GEOADD key longitude latitude member longitude latitude member", "GEOADD key longitude latitude ? longitude latitude ?"),
            ("GEOADD key longitude latitude member", "GEOADD key longitude latitude ?"),
            ("GEOADD key longitude latitude", "GEOADD key longitude latitude"),
            ("GEOADD key", "GEOADD key"),
            ("GEOHASH key", "GEOHASH key"),
            ("GEOPOS key", "GEOPOS key"),
            ("GEODIST key", "GEODIST key"),
            ("GEOHASH key member", "GEOHASH key ?"),
            ("GEOPOS key member", "GEOPOS key ?"),
            ("GEODIST key member", "GEODIST key ?"),
            ("GEOHASH key member member member", "GEOHASH key ?"),
            ("GEOPOS key member member", "GEOPOS key ?"),
            ("GEODIST key member member member", "GEODIST key ?"),
            ("SREM key member1 member2 member3", "SREM key ?"),
            ("ZREM key member1 member2 member3", "ZREM key ?"),
            ("SADD key member1 member2 member3", "SADD key ?"),
            ("GEODIST key member1 member2 m", "GEODIST key ?"),
            ("LPUSH key value1 value2 value3", "LPUSH key ?"),
            ("RPUSH key value1 value2 value3", "RPUSH key ?"),
            ("HSET key field value", "HSET key field ?"),
            ("HSETNX key field value", "HSETNX key field ?"),
            ("HSET key field value field1 value1 field2 value2", "HSET key field ? field1 ? field2 ?"),
            ("HSETNX key field value", "HSETNX key field ?"),
            ("LREM key count value", "LREM key count ?"),
            ("LSET key index value", "LSET key index ?"),
            ("SETBIT key offset value", "SETBIT key offset ?"),
            ("SETRANGE key offset value", "SETRANGE key offset ?"),
            ("SETEX key seconds value", "SETEX key seconds ?"),
            ("PSETEX key milliseconds value", "PSETEX key milliseconds ?"),
            ("ZINCRBY key increment member", "ZINCRBY key increment ?"),
            ("SMOVE source destination member", "SMOVE source destination ?"),
            ("RESTORE key ttl serialized-value [REPLACE]", "RESTORE key ttl ? [REPLACE]"),
            ("LINSERT key BEFORE pivot value", "LINSERT key BEFORE pivot ?"),
            ("LINSERT key AFTER pivot value", "LINSERT key AFTER pivot ?"),
            ("HMSET key field value field value", "HMSET key field ? field ?"),
            ("HMSET key field value", "HMSET key field ?"),
            ("HMSET key field", "HMSET key field"),
            ("MSET key value key value", "MSET key ? key ?"),
            ("MSET", "MSET"),
            ("MSET key value", "MSET key ?"),
            ("MSETNX key value key value", "MSETNX key ? key ?"),
            ("ZADD key score member score member", "ZADD key score ? score ?"),
            ("ZADD key NX score member score member", "ZADD key NX score ? score ?"),
            ("ZADD key NX CH score member score member", "ZADD key NX CH score ? score ?"),
            ("ZADD key NX CH INCR score member score member", "ZADD key NX CH INCR score ? score ?"),
            ("ZADD key XX INCR score member score member", "ZADD key XX INCR score ? score ?"),
            ("ZADD key XX INCR score member", "ZADD key XX INCR score ?"),
            ("ZADD key XX INCR score", "ZADD key XX INCR score"),
            ("CONFIG command SET k v", "CONFIG command SET k ?"),
            ("SET *😊®© ❤️", "SET *😊®© ?"),
            ("SET😊 ❤️*😊®© ❤️", "SET😊 ❤️*😊®© ❤️"),
            ("ZADD key 😊 member score 😊", "ZADD key 😊 ? score ?"),
        ];
    for (input, expected) in testcases.iter() {
        let redis_str = encode_redis_command(input);
        let cmdline = CommandLine::new(&redis_str).unwrap();
        let output = cmdline.stringify(true);
        assert_eq!(
            str::from_utf8(output.as_slice()).unwrap(),
            *expected,
            "testcase {} failed",
            input
        );
    }
}

*/
 */

use crate::helper::Helper;
use crate::attribute::Attribute;
use std::collections::{HashMap};
use std::net::{SocketAddr};

#[allow(non_snake_case)]
pub struct Header{
    pub method: u16,
    pub methodName : String,
    pub length: u16,
    pub transaction_id: [u8;12],
    pub attributes: HashMap<String,Attribute>,
    pub origin: SocketAddr
}

#[allow(non_snake_case)]
impl Header{
    pub const BINDING : u16 = 0x001;
    pub const ALLOCATE : u16 = 0x003;
    pub const REFRESH : u16 = 0x004;
    pub const SEND : u16 = 0x006 | 0b10000;
    pub const DATA : u16 = 0x007 | 0b10000;
    pub const CREATE_PERMISSION : u16 = 0x008;
    pub const CHANNEL_BIND : u16 = 0x009;
    pub const MAGIC : u32 = 0x2112A442;
    pub const MAGIC_MOST : u16 = 0x2112;
    pub const MAGIC_BYTE : [u8;4] = (0x2112A442_u32).to_be_bytes();

    pub fn new(buf: &[u8], Attributes: &HashMap<[u8;2],(String,String)>,origin: SocketAddr) -> Result<Header, String> {
        let method = u16::from_be_bytes(<[u8;2]>::try_from(&buf[0..2]).expect("wrap"));
        let length = u16::from_be_bytes(<[u8;2]>::try_from(&buf[2..4]).expect("blaque"));
        let transaction_id = <[u8;12]>::try_from(&buf[8..20]).expect("Puke");
        let (is_request, methodName) = Header::is_request(method);

        if is_request {
            let attributes = Attribute::getAttributes(buf.get(20..).expect("Oups while doint getAttributes"), Attributes);
            return Ok(Header { method, length, transaction_id, methodName, attributes, origin})
        }

        println!("No request {:x?}", &buf[0..2]);
        println!("SEND {:x?}", &Header::SEND);
        println!("DATA {:x?}", &Header::DATA);

        Err("No request".to_string())
    }

    pub fn from(method:u16,length:u16,transaction_id:[u8;12],origin:SocketAddr) -> Option<Header>{
        let (is_request,methodName) = Header::is_request(method);

        if is_request {
            let attributes = HashMap::new();

            return Some(Header { method, length, transaction_id, methodName, attributes, origin })
        }

        None
    }

    pub fn is_request(method: u16)-> (bool,String) {
        match method {
            Header::BINDING => (true,"Binding".to_string()),
            Header::ALLOCATE => (true, "Allocate".to_string()),
            Header::SEND => (true, "Send".to_string()),
            Header::DATA => (true, "Data".to_string()),
            Header::REFRESH => (true, "Refresh".to_string()),
            Header::CREATE_PERMISSION => (true, "Create_permission".to_string()),
                _ => (false,"".to_string())
        }
    }

    pub fn getResumer(&self){
        let mut attributes  = Vec::new();

        for att in self.attributes.iter() {
            attributes.push(att.1);
        }

        Helper::getResumerHeader(self, &attributes);
    }
}
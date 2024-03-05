use crate::helper::Helper;
use std::collections::HashMap;

pub struct Attribute{
    pub name : String,
    pub value: Vec<u8>,
    pub a_type: String
}

impl Attribute{
    pub const MAPPED_ADDRESS :      [u8;2] = [0x00,0x01];
    pub const USERNAME :            [u8;2] = [0x00,0x06];
    pub const MESSAGE_INTEGRITY :   [u8;2] = [0x00,0x08];
    pub const ERROR_CODE :          [u8;2] = [0x00,0x09];
    pub const UNKNOWN_ATTRIBUTE :   [u8;2] = [0x00,0x0a];
    pub const CHANNEL_NUMBER :      [u8;2] = [0x00,0x0c];
    pub const LIFETIME :            [u8;2] = [0x00,0x0d];
    pub const XOR_PEER_ADDRESS :    [u8;2] = [0x00,0x12];
    pub const DATA :                [u8;2] = [0x00,0x13];
    pub const REALM :               [u8;2] = [0x00,0x14];
    pub const NONCE :               [u8;2] = [0x00,0x15];
    pub const XOR_RELAYED_ADDRESS : [u8;2] = [0x00,0x16];
    pub const REQUESTED_TRANSPORT : [u8;2] = [0x00,0x19];
    pub const XOR_MAPPED_ADDRESS :  [u8;2] = [0x00,0x20];
}

#[allow(non_snake_case)]
impl Attribute{
    pub fn getAttributes(buf: &[u8], Attributes : &HashMap<[u8;2],(String,String)>) -> HashMap<String,Attribute>{
        let mut i = 0;
        let length = buf.len();
        let mut atts = HashMap::new();

        while i < length {
            let last = i;
            let ( name, att, newIndex ) = Attribute::getAttribute(buf.get(i..).unwrap(),i,&Attributes);

            if name == "" {
                println!("Received unkown attribute, type: {:x?} \n", buf.get(i..i+2).unwrap());
            }
            else{
                atts.insert(name,att);
            }

            i = i + newIndex;

            if last == i{
                panic!("Same i twice {:?}",i);
            }
        }

        atts
    }

    #[allow(unused_assignments)]
    pub fn getAttribute(buf: &[u8], mut index:usize, Attributes : &HashMap<[u8;2],(String,String) >) -> ( String, Attribute, usize ){
        let attribute_type = buf.get(0..2).unwrap();
        let arr : [u8;2] = buf.get(2..4).expect("Oh boy").try_into().expect("Oh Girl");
        let length = u16::from_be_bytes(arr) as usize;
        let empty = (String::from(""), String::from(""));
        let (attribute_name,a_type) = match Attributes.get(attribute_type) {
            Some(name) => name,
            None => &empty
        };
        let value = buf.get(4.. 4+length).unwrap().to_vec();
        let mut vv = Vec::new();
        let mut add = 0;

        index = (4 + length) as usize;

        while index % 4 != 0 {
            index = index + 1;
            add = add + 1;
        }

        if attribute_name == ""{
            return ("".to_string(), Attribute { name:"".to_string(), value:Vec::new(), a_type:"".to_string() }, index);
        }

        Helper::add_array_to_vec(&mut vv, &buf.get(0..index).unwrap());

        (attribute_name.to_string(), Attribute { name:String::from(attribute_name), value, a_type:a_type.to_string() }, index)
    }
}
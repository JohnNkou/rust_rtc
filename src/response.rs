use std::collections::HashMap;
use crate::header::Header;
use crate::attribute::Attribute;
use crate::helper::Helper;
use std::net::{SocketAddr,IpAddr};
use md5;
use sha1::{Sha1};
use hmac::{Hmac,Mac};
use std::sync::Arc;


#[allow(non_snake_case)]
pub struct  Response<'a>{
    header: &'a Header,
    attributes: Vec<Attribute>,
    buffer: Vec<u8>
}

#[allow(non_snake_case)]
impl Response<'_>{
    pub fn new(header: &Header) -> Response{

        return Response { header, attributes: Vec::new(), buffer: Vec::new() }
    }

    pub fn getData(&self) -> &[u8]{
        &self.buffer
    }

    pub fn getResumer(&self){
        Helper::getResumer(&self.header, &self.attributes);
    }

    pub fn build(&mut self) -> &Self{
        let length = (self.buffer.len() - 20) as u16;
        let buf = &mut self.buffer;
        let bytes = length.to_be_bytes();

        buf.splice(2..4,bytes);

        self
    }

    pub fn copy_header_info(transaction_id: &[u8],mut buf: &mut Vec<u8>, head_type:u16){
        Helper::add_u16_to_vec(&mut buf, head_type);
        Helper::add_u16_to_vec(&mut buf, 0);
        Helper::add_u32_to_vec(&mut buf, Header::MAGIC);
        Helper::add_array_to_vec(&mut buf, transaction_id);
    }

    pub fn setSuccess(&mut self) -> &mut Self{
        let success = self.header.method | 0b100000000;

        Response::copy_header_info(&self.header.transaction_id,&mut self.buffer,success);

        self
    }

    pub fn setIndication(&mut self) -> &mut Self{
        let tt = self.header.method;

        Response::copy_header_info(&self.header.transaction_id, &mut self.buffer, tt);

        self
    }

    pub fn setFailure(&mut self) -> &mut Self{
        let failure = self.header.method | 0b100010000;

        Response::copy_header_info(&self.header.transaction_id,&mut self.buffer, failure);

        self
    }


    pub fn add_string_attribute(&mut self, att_type: &[u8], value:&str, Attributes: &HashMap<[u8;2], (String,String)>) -> &mut Self{
        let mut buf = &mut self.buffer;

        if buf.len() >= 20 {
            let ( name, a_type ) = Attributes.get(att_type).unwrap();

            Helper::add_array_to_vec(&mut buf, att_type);
            Helper::add_u16_to_vec(&mut buf, value.len() as u16);
            Helper::add_array_to_vec(&mut buf, value.as_bytes());

            self.attributes.push(Attribute { name: name.to_string(), a_type: a_type.to_string(), value:Vec::from(value) });

            Helper::pad_vec(buf, value.len());
        }
        else{
            println!("Response buffer dont have header set");
        }

        self
    }

    pub fn add_number_attribute(&mut self, att_type:&[u8], value:u32, Attributes: &HashMap<[u8;2], (String,String)>) -> &mut Self{
        let mut buf = &mut self.buffer;

        if buf.len() >= 20 {
            let ( name, a_type ) = Attributes.get(att_type).unwrap();

            Helper::add_array_to_vec(&mut buf, att_type);
            Helper::add_u16_to_vec(&mut buf, value.to_be_bytes().len() as u16);
            Helper::add_array_to_vec(&mut buf, &value.to_be_bytes());

            self.attributes.push(Attribute { name: name.to_string(), a_type: a_type.to_string(), value:Vec::from(value.to_be_bytes()) });

            Helper::pad_vec(buf, value.to_be_bytes().len());
        }
        else{
            println!("Response buffer dont have header set");
        }

        self
    }

    pub fn add_xor_attribute(&mut self, att_type: &[u8], addr: &SocketAddr,Attributes: &HashMap<[u8;2],(String,String)>) -> &mut Self{
        let mut buf = &mut self.buffer;

        if buf.len() >=20 {
            let ip = addr.ip();

            match ip {
                IpAddr::V4(ipv4) =>{
                    let ip_bytes = ipv4.octets();
                    let xor_ip = Helper::get_xor_ipv4(ip_bytes);
                    let xor_port = addr.port() ^ Header::MAGIC_MOST;
                    let (name, a_type) = Attributes.get(att_type).unwrap();
                    
                    Helper::add_array_to_vec(&mut buf,att_type);
                    Helper::add_u16_to_vec(&mut buf,8);
                    Helper::add_u16_to_vec(&mut buf, 0x01_u16);
                    Helper::add_u16_to_vec(&mut buf, xor_port);
                    Helper::add_array_to_vec(&mut buf, &xor_ip);

                    let start = buf.len() - 8;

                    self.attributes.push(Attribute { name: name.to_string(), a_type: a_type.to_string(), value:Vec::from(buf.get(start..).unwrap()) });

                },
                IpAddr::V6(_ipv6) =>{

                }
            }   
        }
        else{
            println!("Response buffer dont have header set");
        }

        self
    }

    pub fn add_data_attribute(&mut self, value:&[u8], Attributes: Arc<HashMap<[u8;2],(String,String)>>) -> &mut Self{
        let buf = &mut self.buffer;

        if buf.len() >= 20 {
            let length = value.len() as u16;
            let (name, a_type) = Attributes.get(&Attribute::DATA).unwrap();

            Helper::add_array_to_vec(buf,&Attribute::DATA);
            Helper::add_u16_to_vec(buf,length);
            Helper::add_array_to_vec(buf, value);
            Helper::pad_vec(buf, length as usize);

            self.attributes.push(Attribute { name: name.to_string(), a_type: a_type.to_string(), value: value.to_vec() });
        }
        else{
            panic!("No header set {:x?}", buf);
        }

        self
    }

    pub fn add_integrity(&mut self, Attributes: &HashMap<[u8;2],(String,String)>) -> &mut Self{
        let mut buf = &mut self.buffer;
        let (name, a_type) = Attributes.get(&Attribute::MESSAGE_INTEGRITY).unwrap();

        Helper::add_array_to_vec(&mut buf, &Attribute::MESSAGE_INTEGRITY);
        Helper::add_u16_to_vec(&mut buf, 20_u16);
        Helper::add_array_to_vec(&mut buf, &[0;20]);

        let attrs = buf.get(20..).unwrap();
        let length = attrs.len() as u16;

        buf.splice(2..4, length.to_be_bytes());

        let key = md5::compute("tartar:rtc.abelkashoba.me:pala");
        let end = buf.len() - 24;
        let into : [u8;16] = key.try_into().unwrap();
        let mut hmac : Hmac<Sha1>  = Mac::new_from_slice(&into).expect("MAMAN");
        hmac.update(buf.get(0..end).unwrap());

        let result = hmac.finalize();
        let result_bytes = result.into_bytes();
        let start = (buf.len() - 20) as usize;

        self.attributes.push(Attribute { name: name.to_string(), a_type: a_type.to_string(), value: result_bytes.to_vec() });

        buf.splice(start..,result_bytes);

        self
    }

    pub fn add_error(&mut self, code:u16, reason:&str, Attributes: &HashMap<[u8;2], (String,String)>) -> &mut Self{
        let mut buf = &mut self.buffer;
        let class = (code.div_ceil(100) - 1 ) as u8;
        let number = (code % 100) as u8;
        let length = (4 + reason.len()) as u16;
        let (name, a_type) = Attributes.get(&Attribute::ERROR_CODE).unwrap();

        Helper::add_array_to_vec(&mut buf, &Attribute::ERROR_CODE);
        Helper::add_u16_to_vec(&mut buf, length);
        Helper::add_u16_to_vec(&mut buf, 0_u16);
        Helper::add_u8_to_vec(&mut buf, class);
        Helper::add_u8_to_vec(&mut buf, number);
        Helper::add_array_to_vec(&mut buf, reason.as_bytes());

        Helper::pad_vec(buf, reason.len());


        self.attributes.push(Attribute { name: name.to_string(), a_type: a_type.to_string(), value:Vec::from(code.to_be_bytes())  });

        self
    }
}
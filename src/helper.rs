use crate::header::Header;
use crate::attribute::Attribute;
use std::net::{SocketAddr,IpAddr};

pub struct Helper{

}

impl Helper{
    #[allow(non_snake_case)]
    pub fn getResumerHeader(header: &Header, attributes: &Vec<&Attribute>){
        let length = attributes.len();
        let mut i = 0;

        println!("{:?} Requete {:?}", header.methodName,header.origin);
        println!("Length {:?}", header.length);
        println!("Magic {:x?}", Header::MAGIC);
        println!("Transaction id {:x?} \n", header.transaction_id);

        while i < length{
            let att = &attributes[i];
            let value = &att.value;
            let length = att.value.len();
            let a_type = &att.a_type;

            println!("{:?}", att.name);
            println!("Length: {:?}", length);

            if a_type == "string"{
                println!("Value {:?}", String::from_utf8(value.to_vec()).unwrap());
            }
            else if a_type == "ip"{
                let xor_port = u16::from_be_bytes(value.get(2..4).unwrap().try_into().unwrap());
                let xor_ip = value.get(4..8).unwrap().try_into().unwrap();
                let port = xor_port ^ Header::MAGIC_MOST;
                let ip = Helper::get_xor_ipv4(xor_ip);

                println!("PORT {:?}", port);
                println!("IP {:?}", ip);
                println!("XOR PORT {:?}", xor_port);
                println!("XOR Ip {:?}", value.get(4..8).unwrap());
            }
            else if a_type == "number"{
                println!("Value {:?}", u32::from_be_bytes(value.get(0..).unwrap().try_into().unwrap()));
            }
            else if a_type == "hash" || a_type == "byte"{
                println!("Byte {:x?}", value);
            }

            i = i+1;

            println!("");
        }
    }

    #[allow(non_snake_case)]
    pub fn getResumer(header: &Header, attributes : &Vec<Attribute>){
        let length = attributes.len();
        let mut i = 0;

        println!("{:?} Response {:?}", header.methodName,header.origin);
        println!("Length {:?}", header.length);
        println!("Magic {:x?}", Header::MAGIC);
        println!("Transaction id {:x?} \n", header.transaction_id);

        while i < length{
            let att = &attributes[i];
            let value = &att.value;
            let length = att.value.len();
            let a_type = &att.a_type;

            println!("{:?}", att.name);
            println!("Length: {:?}", length);

            if a_type == "string"{
                println!("Value {:?}", String::from_utf8(value.to_vec()).unwrap());
            }
            else if a_type == "ip"{
                let xor_port = u16::from_be_bytes(value.get(2..4).unwrap().try_into().unwrap());
                let xor_ip = value.get(4..8).unwrap().try_into().unwrap();
                let port = xor_port ^ Header::MAGIC_MOST;
                let ip = Helper::get_xor_ipv4(xor_ip);

                println!("PORT {:?}", port);
                println!("IP {:?}", ip);
                println!("XOR PORT {:?}", xor_port);
                println!("XOR Ip {:?}", value.get(4..8).unwrap());
            }
            else if a_type == "number"{
                println!("Value {:?}", u32::from_be_bytes(value.get(0..).unwrap().try_into().unwrap()));
            }
            else if a_type == "hash" || a_type == "byte"{
                println!("Byte {:x?}", value);
            }
            else{
                println!("UNKWOWN TYPE {:?}", a_type);
            }

            i = i+1;

            println!("\n");
        }
    }

    pub fn pad_vec(vec: &mut Vec<u8>,mut length: usize){
        while length % 4 != 0 {
            length = length + 1;
            vec.push(0);
        }
    }

    pub fn add_u8_to_vec(vec: &mut Vec<u8>, value:u8){
        let byte = value.to_be_bytes();

        vec.push(byte[0]);
    }

    pub fn add_u16_to_vec(vec: &mut Vec<u8>, value: u16){
        let byte = value.to_be_bytes();

        for i in 0..2 {
            vec.push(byte[i]);
        }
    }

    pub fn add_u32_to_vec(vec: &mut Vec<u8>, value: u32){
        let byte = value.to_be_bytes();

        for i in 0..4 {
            vec.push(byte[i]);
        }
    }

    pub fn add_array_to_vec(vec: &mut Vec<u8>, value: &[u8]){
        let length = value.len();

        for i in 0..length {
            vec.push(value[i]);
        }
    }

    pub fn get_attribute_addresse(addresse:&Attribute) -> SocketAddr{
        let value = &addresse.value;
        let port = u16::from_be_bytes(value.get(2..4).unwrap().try_into().unwrap()) ^ Header::MAGIC_MOST;
        let ip = value.get(4..8).unwrap();
        let mut ip_bytes = [0;4];
        let mut i = 0;

        while i < 4{
            ip_bytes[i] = ip[i] ^ Header::MAGIC_BYTE[i];
            i = i + 1;
        }

        let ip = IpAddr::from(ip_bytes);
        let addr = SocketAddr::new(ip, port);

        addr
    }

    pub fn add_xor_port_to_vec(vec: &mut Vec<u8>, value: u16){
        let data = value ^ Header::MAGIC_MOST;

        Helper::add_array_to_vec(vec, &data.to_be_bytes())
    }

    pub fn get_xor_ipv4(ip:[u8;4]) -> [u8;4]{
        let mut xor_ip = [0;4];

        for i in 0..4 {
            xor_ip[i] = ip[i] ^ Header::MAGIC_BYTE[i]
        }

        xor_ip
    }

}

use std::sync::Arc;
use crate::response::Response;
use crate::attribute::Attribute;
use crate::allocation::Allocation;
use crate::header::Header;
use crate::helper::Helper;
use std::net::{UdpSocket,SocketAddr,IpAddr,Ipv4Addr};
use std::collections::HashMap;


pub mod attribute;
pub mod helper;
pub mod header;
pub mod response;
pub mod allocation;

#[allow(non_snake_case)]
fn main(){

    let Attributes = Arc::new(HashMap::from([
        ([0x00,0x01],("MAPPED-ADDRESS".to_string(),     "ip".to_string())),
        ([0x00,0x06],("USERNAME".to_string(),           "string".to_string())),
        ([0x00,0x08],("MESSAGE-INTEGRIRY".to_string(),  "hash".to_string())),
        ([0x00,0x09],("ERROR-CODE".to_string(),         "".to_string())),
        ([0x00,0x0a],("UNKNWON-ATTRIBUTES".to_string(), "".to_string())),
        ([0x00,0x0c],("CHANNEL-NUMBER".to_string(),     "number".to_string())),
        ([0x00,0x0d],("LIFETIME".to_string(),           "number".to_string())),
        ([0x00,0x12],("XOR-PEER-ADDRESS".to_string(),   "ip".to_string())),
        ([0x00,0x13],("DATA".to_string(),               "byte".to_string())),
        ([0x00,0x14],("REALM".to_string(),              "string".to_string())),
        ([0x00,0x15],("NONCE".to_string(),              "string".to_string())),
        ([0x00,0x16],("XOR-RELAYED-ADDRESS".to_string(),"ip".to_string())),
        ([0x00,0x19],("REQUESTED-TRANSPORT".to_string(),"number".to_string())),
        ([0x00,0x20],("XOR-MAPPED-ADDRESS".to_string(), "ip".to_string()))
    ]));
    let mut Allocations : HashMap<SocketAddr,Allocation> = HashMap::new();
    let mut ports = 49152;

    let mut buf = [0;300];
    let socket = UdpSocket::bind("127.0.0.1:8889").expect("Bad");

    loop {
        let (_size, origin) = socket.recv_from(&mut buf).expect("Rad");
        let header = Header::new(&buf[0.._size],&Attributes, origin).expect("Ho, panic on header analyzis");
        let mut response = Response::new(&header);

        header.getResumer();

        if header.methodName == "Binding" {
            let buf = response.setSuccess().add_xor_attribute(&Attribute::XOR_MAPPED_ADDRESS,&origin,&Attributes).build().getData();

            socket.send_to(buf,origin).unwrap();
            response.getResumer();
        }
        else if header.methodName == "Send"{
            match header.attributes.get("XOR-PEER-ADDRESS"){
                Some(attribute)=>{

                    match header.attributes.get("DATA"){
                        Some(data_attribute)=>{
                            match Allocations.get(&origin){
                                Some(alloc)=>{
                                    let addr = Helper::get_attribute_addresse(&attribute);
                                    let socket = alloc.socket.clone();
                                    let data = &data_attribute.value;

                                    socket.send_to(data,addr).unwrap();

                                    println!("DATA RELAYED FROM {:?} TO {:?}", socket.local_addr().unwrap(), addr);
                                    println!("RELAYED DATA {:x?}", data);
                                },
                                None =>{
                                    println!("NO ALLOCATION FOUND FOR {:?}", origin);
                                }
                            }
                        },
                        None =>{
                            println!("NO DATA ATTRIBUTE FOR SEND METHOD {:?}", origin);
                        }
                    }
                },
                None => {
                    println!("No xor peer address found");
                }
            }
        }
        else if header.methodName == "Allocate" {
            let hasIntegrity = match header.attributes.get("MESSAGE-INTEGRIRY"){
                Some(_Attribute) => true,
                None => false
            };

            if hasIntegrity {
                let hasUsername = match header.attributes.get("USERNAME"){
                    Some(_Attribute) => true,
                    _None => false
                };
                let hasRealm = match header.attributes.get("REALM"){
                    Some(_Attribute) => true,
                    None => false
                };
                let hasNonce = match header.attributes.get("NONCE"){
                    Some(_Attribute) => true,
                    None => false
                };
                let hasRequested_Transport = match header.attributes.get("REQUESTED-TRANSPORT"){
                    Some(_Attribute) => true,
                    None => false
                };

                if hasUsername && hasRealm && hasNonce{
                    if hasRequested_Transport {
                        let alloc = Allocation::new(ports,origin.clone(), Attributes.clone());
                        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127,0,0,1)),ports);

                        Allocations.insert(origin.clone(),alloc);

                        response.setSuccess();
                        response.add_xor_attribute(&Attribute::XOR_RELAYED_ADDRESS,&addr,&Attributes);
                        response.add_xor_attribute(&Attribute::XOR_MAPPED_ADDRESS,  &origin,&Attributes).add_number_attribute(&Attribute::LIFETIME,600,&Attributes);
                        response.add_integrity(&Attributes).build();

                        socket.send_to(response.getData(),origin).unwrap();

                        ports = ports + 1;
                    }
                    else{
                        response.setFailure().add_error(400,"Bad Request",&Attributes).add_integrity(&Attributes).build();

                        socket.send_to(response.getData(),origin).unwrap();
                    }
                }
                else{
                    response.setFailure().add_error(400,"Bad Request",&Attributes).build();

                    let buf = response.getData();

                    println!("Response {:?}", buf);

                    socket.send_to(buf,origin).unwrap();
                }
                
            }
            else{
                response.setFailure().add_string_attribute(&Attribute::REALM,"rtc.abelkashoba.me",&Attributes).add_string_attribute(&Attribute::NONCE,"2020",&Attributes);
                response.add_error(401,"Unauthorized",&Attributes).build();

                let buf = response.getData();

                socket.send_to(buf,origin).unwrap();
            }

            response.getResumer();

        }
        else if header.methodName == "Refresh"{
            match header.attributes.get("LIFETIME"){
                Some(lifetime) => {
                    let buf = &lifetime.value;
                    let number = u32::from_be_bytes(<[u8;4]>::try_from(&buf[0..4]).unwrap());
                    let mut chosen_number = 0;

                    if number != 0 {
                        chosen_number = 600;
                    }

                    response.setSuccess().add_number_attribute(&Attribute::LIFETIME, chosen_number, &Attributes);
                },
                None =>{
                    response.setFailure().add_error(400,"Couldn't retrieve the LIFETIME Attribute",&Attributes);
                }
            }

            response.add_integrity(&Attributes);
            response.build();

            socket.send_to(response.getData(), origin).unwrap();

            response.getResumer();
        }
        else if header.methodName == "Create_permission"{
            match header.attributes.get("XOR-PEER-ADDRESS"){
                Some(attribute) => {
                    match Allocations.get_mut(&origin){
                        Some(alloc)=>{
                            let peerAddr = Helper::get_attribute_addresse(&attribute);
                            let cloned = peerAddr.clone();

                            alloc.add_peer(peerAddr);

                            println!("Peer Address {:?} added", cloned);
                            response.setSuccess();
                        },
                        None =>{
                            response.setFailure().add_error(400,"Not found",&Attributes);
                        }
                    }
                },
                None =>{
                    response.setFailure();
                    response.add_error(400,"No peer address found",&Attributes);
                }
            }

            response.add_integrity(&Attributes).build();

            socket.send_to(response.getData(), origin).unwrap();

            response.getResumer();

        }
        else{
            println!("method not knwon {:?}", buf.get(0..2).unwrap());
        }
    }
}
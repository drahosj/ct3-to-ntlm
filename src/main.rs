use clap::*;
use hex;

mod app;
mod des;

use app::*;

fn main() {
    let m = Command::new("NTLMv1 Challenge to NTLM hash program")
    .author("Virgile, Almandin virgilejarry@mailbox.org")
    .version("1.0.0")
    .about("This program aims to help auditors to convert NTLMv1 challenge obtained through Responder.py to a full NTLM hash.")
    .arg(
        Arg::new("challresp").help("The output of responder in the following forms :
        'hashcat::DUSTIN-5AA37877:8D3A906B51ADC361BB3591FB409E10A6772122DF2A1DF4CF:FC555459FBCF81DAF3A5714B6BB70EAD6ACDD9220837431F:3ff1ec58232fa46d'
        or
        'hashcat::DUSTIN-5AA37877:6DC94494429127B800000000000000000000000000000000:713D5E0956A34F7897CCCA1DDC6FC73DE4C7BB5445B8C542:1122334455667788'")
        .required(true)
    )
    .after_help("This program takes an NTLMv1 response obtained from Responder.py and does all the work to give everything\
     needed to easily crack it to get an NTLM hash with crack.sh and by decoding automatically the last two bytes of the hash\
     without having to call an external program.")
    .get_matches();
    let data = m.value_of("challresp").expect("Something went wrong with clap...");
    let elements: Vec<&str> = data.split(':').collect();
    if elements.len() != 6 {
        panic!("Your challenge response doesnt seem to be correctly formatted. It should be in the following form : 
        username:whatever:hostname:LMResp:NTResp:clientchall");
    }
    let lm_response_str = elements[3];
    let nt_response_str = elements[4];
    let client_challenge_str = elements[5];
    let mut lm_response: [u8;24] = [0;24];
    let mut nt_response: [u8; 24] = [0; 24];
    let mut client_challenge: [u8; 8] = [0; 8];

    hex::decode_to_slice(lm_response_str, &mut lm_response).expect("Badly formatted ntlmv1 challenge/response ...");
    hex::decode_to_slice(nt_response_str, &mut nt_response).expect("Badly formatted ntlmv1 challenge/response ...");
    hex::decode_to_slice(client_challenge_str, &mut client_challenge).expect("Badly formatted ntlmv1 challenge/response ...");
    //let ct1 = &nt_response[..16];
    //let ct2 = &nt_response[16..32];
    let ct3 = &nt_response[16..];

    let result = match lm_response[8..].iter().all(|e| *e == 0) {
        true => ct3_to_ntlm(ct3, &client_challenge, Some(&lm_response)), // with ssp
        false => ct3_to_ntlm(ct3, &client_challenge, None) // without ssp
    };
    match result {
        Some(s) => println!("{s}"),
        None => println!("No key found to match this challenge. Three possibilities here : 
        1. You failed when copy/pasting your challenge from Responder ;
        2. Responder is drunk ;
        3. Windows is drunk.")
    }
}

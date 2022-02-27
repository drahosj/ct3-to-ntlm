use bitvec::prelude::*;
use md5;

use crate::des;

pub fn ct3_to_ntlm(ct3: &[u8], client_challenge: &[u8], lm_response: Option<&[u8]>) -> Option<String> {
    let challenge: Vec<u8>;
    
    match lm_response {
        Some(lm) => {
            let c = [client_challenge, &lm[..8]].concat();
            let digest = md5::compute(c);
            challenge = Vec::from(&digest[..8]);
        },
        None => {
            challenge = Vec::from(client_challenge);
        }
    }
    let mut parited_key: Vec<u8> = vec![0; 8];
    let mut decrypted_data: Vec<u8> = vec![0; 8];
    for i in 0..=255 {
        for j in 0..=255 {
            let k = &[i, j, 0, 0, 0, 0, 0];
            odd_parity(k, &mut parited_key);
            des::decrypt(ct3, &parited_key, &mut decrypted_data);
            if decrypted_data == challenge {
                return Some(format!("{i:x}{j:x}"));
            }
        }
    }
    None
}
//pain in the a**, please submit a PR to simplify this
// it takes a 7 bytes long &[u8] and replaces the 8 first bytes of the result vector
// with the input key, odd parity bits added
// used this to debug : https://limbenjamin.com/articles/des-key-parity-bit-calculator.html 
// the choice to push data in a &mut vector is for speed, we dont have to allocate data in a 256*256 loop.
pub fn odd_parity(small_key: &[u8], long_key: &mut Vec<u8>) {
    let mut finalbits: BitVec<u8, Msb0> = BitVec::from_slice(small_key);
    for i in 0..8 {
        let start = (7 - i) * 7;
        let end = start + 7;
        let s = finalbits.get(start..end).unwrap();
        if s.count_ones() % 2 == 0{
            //even
            finalbits.insert(end, true);
        } else {
            finalbits.insert(end, false);
        }
    }
    long_key.clear();
    finalbits.chunks(8).for_each(|bs|{
        let mut res: u8 = 0;
        bs.iter().rev().enumerate().for_each(|(i, b)|{
            if *b {
                res += (2 as u8).pow(i as u32);
            }
        });
        long_key.push(res);

    });
}
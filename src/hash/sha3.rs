// // Reference: FIPS 202 (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
// //                     (file:///C:/Users/Gaspard/Downloads/A_New_High_Throughput_and_Area_Efficient_SHA_3_Implementation.pdf)
// //                     (https://keccak.team/files/Keccak-reference-3.0.pdf)
//
// // A[x, y, z]=S[w(5y + x) + z]
//
//
// const W: usize = 32;
//
//
// macro_rules! get_cell {
//     ($state:expr, $i:expr, $j:expr, $k:expr) => {
//         ($state)[W * (5 * ($j) + ($i)) + ($k)]
//     };
// }
//
// fn phi(state: &mut [u8]) {
//     let mut c = [0u8; 5 * W];
//     let mut d = [0u8; 5 * W];
//
//     for z in 0..W {
//         for x in 0..5usize {
//             c[z * W + x] = get_cell!(state, x, 0, z) ^ get_cell!(state, x, 1, z)
//                          ^ get_cell!(state, x, 2, z) ^ get_cell!(state, x, 3, z)
//                          ^ get_cell!(state, x, 4, z);
//         }
//     }
//
//     for z in 0..W {
//         for x in 0..5usize {
//             d[z * 5 + x] = c[z * 5 + (x - 1) % 5] ^ c[((z - 1) % W) * 5 + (x + 1) % 5];
//         }
//     }
//
//     for z in 0..W {
//         for x in 0..5usize {
//             for y in 0..5usize {
//                 get_cell!(state, x, y, z) ^= d[z * 5 + x];
//             }
//         }
//     }
// }
//
//
// fn rho(state: &mut [u8]) {
//     let mut x = 1;
//     let mut y = 0;
//
//     for t in 0..24usize {
//         for z in 0..W {
//             get_cell!(state, x, y, z) = get_cell!(state, x, y, (z - (t + 1) * (t + 2) / 2) % W);
//             (x, y) = (y, (2 * x + 3 * y) % 5);
//         }
//     }
// }
//
//
// fn pi(state: &mut [u8]) {
//     for z in 0..W {
//         for x in 0..5usize {
//             for y in 0..5usize {
//                 get_cell!(state, x, y, z) = get_cell!(state, (x + 3 * y) % 5, y, z);
//             }
//         }
//     }
// }
//
//
// fn chi(state: &mut [u8]) {
//     for z in 0..W {
//         for x in 0..5usize {
//             for y in 0..5usize {
//                 get_cell!(state, x, y, z) ^=
//                     get_cell!(state, (x + 1) % 5, y, z) & get_cell!(state, (x + 2) % 5, y, z);
//             }
//         }
//     }
// }
//
//
// fn rc(t: u32) -> u8 {
//     let mut r = 0b10000000u32;
//     let nloop = t % 255;
//
//     for i in 0..nloop {
//         let lastbit = (r >> 8) & 1;
//         // r.rotate_right(1);
//     }
//
//     r as u8
// }
//

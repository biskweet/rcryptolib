use rcryptolib::hash::sha2::sha2;

#[test]
fn t_sha2() {
    let result = sha2(&[]);
    let target : [u8; 32] = [227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85];
    assert!(result.iter().eq(target.iter()), "Test 1 failed");

    let result = sha2(&[0]);
    let target : [u8; 32] = [110, 52, 11, 156, 255, 179, 122, 152, 156, 165, 68, 230, 187, 120, 10, 44, 120, 144, 29, 63, 179, 55, 56, 118, 133, 17, 163, 6, 23, 175, 160, 29];
    assert!(result.iter().eq(target.iter()), "Test 2 failed");

    let result = sha2("1VFDrWq_bX4Glh6s-1yzEceXaTkouV8jUs4lSa5nM2QmyTMVaSRmweSHT4E4AUYBGuHQbuulz_-iEe_U_nGwMQV1On2M7Gbcl1jjmsCej1yk".as_bytes());
    let target : [u8; 32] = [81, 97, 147, 138, 212, 245, 12, 105, 110, 186, 187, 156, 229, 158, 5, 149, 182, 97, 168, 143, 74, 100, 181, 241, 40, 200, 21, 38, 188, 31, 88, 240];
    assert!(result.iter().eq(target.iter()), "Test 3 failed");

    let result = sha2("uMUW8t90GWM-_vg2v8VNzhx-K8U".as_bytes());
    let target : [u8; 32] = [9, 92, 29, 56, 166, 92, 124, 201, 1, 231, 88, 209, 249, 169, 239, 39, 152, 102, 69, 71, 176, 184, 55, 36, 140, 249, 160, 12, 157, 78, 6, 171];
    assert!(result.iter().eq(target.iter()), "Test 4 failed");

    let result = sha2("LbBkaCTL5VUqhr6WSL7DgtRBmDY6ZeA3ipzcVrjsSnGQ57VhwptxYPtpbH0".as_bytes());
    let target : [u8; 32] = [69, 94, 73, 18, 13, 171, 114, 120, 15, 13, 224, 16, 186, 134, 160, 227, 178, 178, 176, 178, 68, 14, 3, 134, 228, 247, 180, 202, 175, 144, 34, 93];
    assert!(result.iter().eq(target.iter()), "Test 5 failed");

    let result = sha2("93z_oapwfTOU1nLVvPnQpNIx9rMQyVxGvBYplMNpWVXGC7Kcoev3d3uAW5Ini_VItDkWbnmcyCzN3vw1HYrF".as_bytes());
    let target : [u8; 32] = [81, 242, 71, 163, 80, 130, 97, 99, 57, 154, 177, 22, 231, 240, 11, 246, 192, 142, 128, 240, 72, 243, 132, 96, 146, 90, 52, 233, 37, 125, 38, 105];
    assert!(result.iter().eq(target.iter()), "Test 6 failed");

    let result = sha2("atBZ55UkeBsf-W6pzdl63Ee0Du-1luKAXQCVPMiwHdHdIC0oS36YRfG-k5Y8W7LfuS5sRVpkzmYjqXiN6DhaWQ".as_bytes());
    let target : [u8; 32] = [86, 84, 165, 202, 123, 12, 223, 159, 87, 91, 74, 31, 228, 225, 209, 57, 13, 113, 23, 136, 139, 21, 172, 29, 179, 119, 76, 139, 234, 181, 5, 155];
    assert!(result.iter().eq(target.iter()), "Test 7 failed");

    let result = sha2("UiP2n7Rg5nGkZeb7Yt1c4PxCvOIYAGhlYzaEIURbJD9_MNw3YBpWAld2zBSWEwFHRC0kHjY7jjewUsQYPlmXFJo".as_bytes());
    let target : [u8; 32] = [129, 134, 231, 108, 34, 193, 11, 4, 50, 201, 109, 187, 254, 234, 142, 27, 239, 194, 5, 22, 11, 208, 207, 136, 90, 209, 49, 214, 228, 60, 236, 189];
    assert!(result.iter().eq(target.iter()), "Test 8 failed");
}
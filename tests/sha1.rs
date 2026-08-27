use rcryptolib::hash::sha1::sha1;

#[test]
fn t_sha1() {
    let result = sha1(&[]);
    let target : [u8; 20] = [218, 57, 163, 238, 94, 107, 75, 13, 50, 85, 191, 239, 149, 96, 24, 144, 175, 216, 7, 9];
    assert!(result.iter().eq(target.iter()), "Test 1 failed");

    let result = sha1(&[0]);
    let target : [u8; 20] = [91, 169, 60, 157, 176, 207, 249, 63, 82, 181, 33, 215, 66, 14, 67, 246, 237, 162, 120, 79];
    assert!(result.iter().eq(target.iter()), "Test 2 failed");

    let result = sha1("1VFDrWq_bX4Glh6s-1yzEceXaTkouV8jUs4lSa5nM2QmyTMVaSRmweSHT4E4AUYBGuHQbuulz_-iEe_U_nGwMQV1On2M7Gbcl1jjmsCej1yk".as_bytes());
    let target : [u8; 20] = [29, 146, 40, 232, 43, 63, 25, 229, 22, 61, 196, 62, 204, 122, 81, 253, 170, 162, 56, 109];
    assert!(result.iter().eq(target.iter()), "Test 3 failed");

    let result = sha1("uMUW8t90GWM-_vg2v8VNzhx-K8U".as_bytes());
    let target : [u8; 20] = [156, 125, 247, 244, 218, 5, 2, 143, 47, 93, 212, 209, 175, 238, 148, 193, 154, 67, 158, 157];
    assert!(result.iter().eq(target.iter()), "Test 4 failed");

    let result = sha1("LbBkaCTL5VUqhr6WSL7DgtRBmDY6ZeA3ipzcVrjsSnGQ57VhwptxYPtpbH0".as_bytes());
    let target : [u8; 20] = [168, 108, 135, 90, 213, 243, 253, 6, 59, 185, 111, 151, 240, 21, 69, 181, 65, 227, 52, 172];
    assert!(result.iter().eq(target.iter()), "Test 5 failed");

    let result = sha1("93z_oapwfTOU1nLVvPnQpNIx9rMQyVxGvBYplMNpWVXGC7Kcoev3d3uAW5Ini_VItDkWbnmcyCzN3vw1HYrF".as_bytes());
    let target : [u8; 20] = [73, 78, 2, 119, 229, 149, 230, 145, 169, 133, 21, 38, 58, 105, 50, 204, 205, 46, 193, 36];
    assert!(result.iter().eq(target.iter()), "Test 6 failed");

    let result = sha1("atBZ55UkeBsf-W6pzdl63Ee0Du-1luKAXQCVPMiwHdHdIC0oS36YRfG-k5Y8W7LfuS5sRVpkzmYjqXiN6DhaWQ".as_bytes());
    let target : [u8; 20] = [63, 203, 79, 47, 91, 95, 171, 184, 66, 64, 144, 61, 50, 140, 235, 235, 150, 230, 10, 167];
    assert!(result.iter().eq(target.iter()), "Test 7 failed");

    let result = sha1("UiP2n7Rg5nGkZeb7Yt1c4PxCvOIYAGhlYzaEIURbJD9_MNw3YBpWAld2zBSWEwFHRC0kHjY7jjewUsQYPlmXFJo".as_bytes());
    let target : [u8; 20] = [195, 126, 204, 91, 8, 136, 244, 83, 209, 90, 168, 181, 61, 128, 24, 100, 255, 146, 18, 22];
    assert!(result.iter().eq(target.iter()), "Test 8 failed");
}
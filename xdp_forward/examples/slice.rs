


fn main() {
    let x: [u8; 5] = [1,2,3,4,5];
    println!("{}", x.len());
    let y = x[..2];
    println!("{}", y.len());

    println!("Array size: {}", std::mem::size_of_val(&x)); // 输出: Array size: 5
    println!("Slice size: {}", std::mem::size_of_val(&y)); // 输出: Slice size: 16 (在64位系统上)

}

fn main() {
    println!("cargo:rerun-if-changed=src/risk_csv.csv");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "proto/pakeles/ir/v1alpha1/ir.proto";
    println!("cargo:rerun-if-changed={proto}");
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
    let descriptor = out.join("ir_descriptor.bin");
    prost_build::Config::new()
        .file_descriptor_set_path(&descriptor)
        .boxed(".pakeles.ir.v1alpha1.BinOp.lhs")
        .boxed(".pakeles.ir.v1alpha1.BinOp.rhs")
        .compile_protos(&[proto], &["proto"])?;
    pbjson_build::Builder::new()
        .register_descriptors(&std::fs::read(&descriptor)?)?
        .build(&[".pakeles.ir.v1alpha1"])?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protos = [
        "proto/pakeles/ir/v1alpha1/ir.proto",
        "proto/pakeles/testvec/v1alpha1/testvec.proto",
    ];
    for p in &protos {
        println!("cargo:rerun-if-changed={p}");
    }
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
    let descriptor = out.join("descriptor.bin");
    prost_build::Config::new()
        .file_descriptor_set_path(&descriptor)
        .boxed(".pakeles.ir.v1alpha1.BinOp.lhs")
        .boxed(".pakeles.ir.v1alpha1.BinOp.rhs")
        .compile_protos(&protos, &["proto"])?;
    pbjson_build::Builder::new()
        .register_descriptors(&std::fs::read(&descriptor)?)?
        .build(&[".pakeles.ir.v1alpha1", ".pakeles.testvec.v1alpha1"])?;
    Ok(())
}

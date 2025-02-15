param($arg0)

$env:RUSTFLAGS = "-Z remap-cwd-prefix=."
if ($arg0 -ne "debug") {
    cross +nightly build --release --target x86_64-pc-windows-msvc
    cross +nightly build --release --target x86_64-unknown-linux-gnu
}
else {
    cross +nightly build --target x86_64-pc-windows-msvc
}
$env:RUSTFLAGS = ""


if ($arg0 -ne "debug") {
    Copy-Item -Path target/x86_64-pc-windows-msvc/release/dsd_ghidra.dll -Destination dsd-ghidra/src/main/resources/win32-x86-64/
    Copy-Item -Path target/x86_64-unknown-linux-gnu/release/libdsd_ghidra.so -Destination dsd-ghidra/src/main/resources/linux-x86-64/
}
else {
    Copy-Item -Path target/x86_64-pc-windows-msvc/debug/dsd_ghidra.dll -Destination dsd-ghidra/src/main/resources/win32-x86-64/
    Copy-Item -Path target/x86_64-pc-windows-msvc/debug/dsd_ghidra.pdb -Destination dsd-ghidra/src/main/resources/win32-x86-64/
}

rm -rf target/data
mkdir target/data

/nix/store/2d328zax57k8nskvqbkz8k3y5imb0y62-swtpm-wrappers/bin/swtpm_setup --tpm2 \
    --tpmstate target/data \
    --createek --allow-signing --decryption --create-ek-cert \
    --create-platform-cert \
    --display
/nix/store/2d328zax57k8nskvqbkz8k3y5imb0y62-swtpm-wrappers/bin/swtpm socket \
    -p 2321 --ctrl type=tcp,port=2322 \
    --tpmstate dir=target/data  --tpm2 \
    --log fd=1,level=5 \
    --flags startup-clear

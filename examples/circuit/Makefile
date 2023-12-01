all: plonk

setup:
	git clone --quiet https://github.com/iden3/circom.git 
	cd circom && cargo build --release && cargo install --path circom
	npm install -g snarkjs
	
plonk:
	# phase1
	snarkjs powersoftau new bn128 14 phase1_start.ptau -v
	snarkjs powersoftau contribute phase1_start.ptau phase1_end.ptau --name="First contribution" -v

	# start of phase 2 (but don't do the phase 2)
	snarkjs powersoftau prepare phase2 phase1_end.ptau phase2_start.ptau -v

	# compile
	circom circuit.circom --r1cs --wasm --sym

	# create zkey
	snarkjs plonk setup circuit.r1cs phase2_start.ptau circuit_final.zkey

	# export vk
	snarkjs zkey export verificationkey circuit_final.zkey vk.json

	# prove
	node output/circuit_js/generate_witness.js output/circuit_js/circuit.wasm public_inputs.json output/witness.wtns
	snarkjs plonk prove circuit_final.zkey output/witness.wtns proof.json proof_inputs.json

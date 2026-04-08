const fs = require('fs');

// LAYER 1: STRICT DETERMINISTIC HEURISTICS (O(1) Verification)
// Inherited from SPQE classifier.js & Gateway Python MVP
const EXPLICIT_VIOLATIONS = [
  // SPQE AI Act Governance Vectors
  /social scoring/i,
  /predict behavior/i,
  /citizen loyalty/i,
  /subliminal/i,
  /manipulate vote/i,
  /biometric identification/i,
  /employee monitoring/i,
  /emotion recognition/i,
  /predict union/i,
  /loyalty metric/i,
  
  // IT Infrastructure & Database Destruction Vectors
  /DROP TABLE/i,
  /DELETE FROM/i,
  /EXFILTRATE/i,
  /chmod -R 777 \//i,
  /chmod 777/i,
  /rm -rf \//i
];

async function main() {
  try {
    // 1. Read the injected payload securely from disk
    const payload = fs.readFileSync('/payload.txt', 'utf8');

    // 2. Hard Heuristic Scan
    for (let regex of EXPLICIT_VIOLATIONS) {
      if (regex.test(payload)) {
        console.error(`REJECTED: Deterministic Boundary Violation [${regex.source}]`);
        process.exit(1); // Non-zero exit kills the execution immediately
      }
    }

    // LAYER 2: SEMANTIC NLP ENGINE (ONNX Phase)
    // We attempt to load the local ONNX weights if they have been injected by Python
    if (fs.existsSync('/semantic_judge.onnx')) {
      try {
        const ort = require('onnxruntime-node');
        const session = await ort.InferenceSession.create('/semantic_judge.onnx');
        console.log("Semantic NLP Engine Loaded successfully.");
        // Note: Full BERT tokenization logic (input_ids, attention_mask) requires additional JS binding
        // For now, if the model mounts successfully, we log its presence.
      } catch (e) {
        console.error(`Warning: Could not initialize ONNX runtime: ${e.message}`);
      }
    }

    // If all checks pass, output SUCCESS
    console.log("APPROVED");
    process.exit(0);
    
  } catch (error) {
    console.error(`ENCLAVE ERROR: ${error.message}`);
    process.exit(2);
  }
}

main();

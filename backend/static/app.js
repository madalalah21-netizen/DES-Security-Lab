
// ==========================================
// DES SECURITY LAB
// Frontend JavaScript
// Encryption, Decryption & Round Trace
// ==========================================

const plaintextInput = document.getElementById("plaintextInput");
const keyInput = document.getElementById("keyInput");
const encryptButton = document.getElementById("encryptButton");
const ciphertextOutput = document.getElementById("ciphertextOutput");
const encryptMessageStatus = document.getElementById("encryptMessage");

const decryptInput = document.getElementById("decryptInput");
const decryptKeyInput = document.getElementById("decryptKeyInput");
const decryptButton = document.getElementById("decryptButton");
const decryptedOutput = document.getElementById("decryptedOutput");
const decryptMessageStatus = document.getElementById("decryptMessage");

// ==========================================
// ROUND TRACE CONTAINER
// ==========================================

let traceContainer = document.getElementById("roundTrace");

if (!traceContainer) {
    traceContainer = document.createElement("section");
    traceContainer.id = "roundTrace";
    traceContainer.className = "workbench-panel";
    traceContainer.style.marginTop = "24px";

    traceContainer.innerHTML = `
        <h2>DES Encryption Round Trace</h2>
        <p>Detailed internal state for each DES block and round.</p>
        <div id="traceContent"></div>
    `;

    const workbench = document.querySelector(".workbench-section");

    if (workbench) {
        workbench.appendChild(traceContainer);
    }
}

// ==========================================
// MESSAGE HANDLER
// ==========================================

function showMessage(element, message, success = true) {
    if (!element) return;

    element.textContent = message;
    element.style.color = success ? "#16a34a" : "#dc2626";
}

// ==========================================
// DISPLAY DES ROUND TRACE
// ==========================================

function displayTrace(data) {
    const content = document.getElementById("traceContent");

    if (!content) return;

    content.innerHTML = "";

    if (!data.blocks || data.blocks.length === 0) {
        content.textContent = "No round trace available.";
        return;
    }

    const orderedBlocks = [...data.blocks].sort(
        (a, b) => a.block_number - b.block_number
    );

    orderedBlocks.forEach(block => {
        const blockSection = document.createElement("div");
        blockSection.className = "trace-block";

        const heading = document.createElement("h3");
        heading.textContent = `BLOCK ${block.block_number}`;
        heading.className = "trace-block-title";

        blockSection.appendChild(heading);

        const tableWrapper = document.createElement("div");
        tableWrapper.className = "trace-table-wrapper";

        const table = document.createElement("table");
        table.className = "trace-table";

        const thead = document.createElement("thead");
        const header = document.createElement("tr");

        ["Round", "Left (L)", "Right (R)", "Round Key"].forEach(label => {
            const th = document.createElement("th");
            th.textContent = label;
            header.appendChild(th);
        });

        thead.appendChild(header);
        table.appendChild(thead);

        const tbody = document.createElement("tbody");

        const orderedRounds = [...block.rounds].sort(
            (a, b) => a.round - b.round
        );

        orderedRounds.forEach(round => {
            const row = document.createElement("tr");

            const values = [
                String(round.round).padStart(2, "0"),
                round.left,
                round.right,
                round.round_key
            ];

            values.forEach((value, index) => {
                const td = document.createElement("td");
                td.textContent = value;

                td.className = index === 0
                    ? "trace-round-number"
                    : "trace-hex-value";

                row.appendChild(td);
            });

            tbody.appendChild(row);
        });

        table.appendChild(tbody);
        tableWrapper.appendChild(table);
        blockSection.appendChild(tableWrapper);
        content.appendChild(blockSection);
    });
}

// ==========================================
// ENCRYPTION
// ==========================================

async function handleEncryption() {
    const plaintext = plaintextInput.value.trim();
    const key = keyInput.value.trim();

    if (!plaintext || !key) {
        showMessage(encryptMessageStatus, "Please enter plaintext and key.", false);
        return;
    }

    encryptButton.disabled = true;
    showMessage(encryptMessageStatus, "Encrypting...");

    try {
        const response = await fetch("/api/encrypt/trace", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                plaintext: plaintext,
                key: key
            })
        });

        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error(data.error || "Encryption failed.");
        }

        ciphertextOutput.value = data.ciphertext;
        decryptInput.value = data.ciphertext;
        decryptKeyInput.value = key;

        displayTrace(data);

        showMessage(
            encryptMessageStatus,
            "Encryption completed successfully. Round trace generated."
        );

    } catch (error) {
        showMessage(encryptMessageStatus, error.message, false);

    } finally {
        encryptButton.disabled = false;
    }
}

// ==========================================
// DECRYPTION
// ==========================================

async function handleDecryption() {
    const ciphertext = decryptInput.value.trim();
    const key = decryptKeyInput.value.trim();

    if (!ciphertext || !key) {
        showMessage(decryptMessageStatus, "Please enter ciphertext and key.", false);
        return;
    }

    decryptButton.disabled = true;
    showMessage(decryptMessageStatus, "Decrypting...");

    try {
        const response = await fetch("/api/decrypt", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                ciphertext: ciphertext,
                key: key
            })
        });

        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error(data.error || "Decryption failed.");
        }

        decryptedOutput.value = data.plaintext;

        showMessage(
            decryptMessageStatus,
            "Decryption completed successfully."
        );

    } catch (error) {
        showMessage(decryptMessageStatus, error.message, false);

    } finally {
        decryptButton.disabled = false;
    }
}

// ==========================================
// ENCRYPTION / DECRYPTION EVENTS
// ==========================================

if (encryptButton) {
    encryptButton.addEventListener("click", handleEncryption);
}

if (decryptButton) {
    decryptButton.addEventListener("click", handleDecryption);
}

// ==========================================
// INITIALIZATION
// ==========================================

console.log("DES Security Lab JavaScript loaded successfully.");

// ==========================================
// BRUTE FORCE LAB
// ==========================================

(() => {
    const plaintextInput = document.getElementById("brutePlaintext");
    const ciphertextInput = document.getElementById("bruteCiphertext");
    const keyBitsInput = document.getElementById("bruteKeyBits");
    const attackButton = document.getElementById("bruteForceButton");

    const messageOutput = document.getElementById("bruteForceMessage");
    const statusOutput = document.getElementById("bruteForceStatus");
    const recoveredKeyOutput = document.getElementById("bruteRecoveredKey");

    const candidateOutput = document.getElementById("bruteCandidate");
    const attemptsOutput = document.getElementById("bruteAttempts");
    const totalKeysOutput = document.getElementById("bruteTotalKeys");
    const elapsedOutput = document.getElementById("bruteElapsed");

    const resultElements = [
        messageOutput,
        statusOutput,
        recoveredKeyOutput,
        candidateOutput,
        attemptsOutput,
        totalKeysOutput,
        elapsedOutput
    ];

    if (!attackButton || resultElements.some(element => !element)) {
        console.error("Brute Force Lab: One or more HTML elements are missing.");
        return;
    }

    function showBruteMessage(message, type = "") {
        messageOutput.textContent = message;
        messageOutput.className = "workbench-message";

        if (type) {
            messageOutput.classList.add(type);
        }
    }

    function resetBruteResults() {
        statusOutput.textContent = "Attack in progress...";
        recoveredKeyOutput.value = "";

        candidateOutput.textContent = "—";
        attemptsOutput.textContent = "—";
        totalKeysOutput.textContent = "—";
        elapsedOutput.textContent = "—";
    }

    function displayAttackResults(data) {
        statusOutput.textContent = data.found ? "KEY FOUND" : "KEY NOT FOUND";

        recoveredKeyOutput.value = data.found
            ? (data.key || "Unavailable")
            : "Not recovered";

        candidateOutput.textContent = data.found
            ? String(data.candidate)
            : "—";

        attemptsOutput.textContent =
            Number(data.attempts ?? 0).toLocaleString();

        totalKeysOutput.textContent =
            Number(data.total_keys ?? 0).toLocaleString();

        elapsedOutput.textContent =
            Number(data.elapsed_seconds ?? 0).toFixed(6) + " s";
    }

    attackButton.addEventListener("click", async () => {
        const plaintext = plaintextInput.value.trim();
        const ciphertext = ciphertextInput.value.trim().replace(/\s+/g, "");
        const keyBits = Number(keyBitsInput.value);

        if (!plaintext) {
            showBruteMessage("Please enter the known plaintext.", "error");
            plaintextInput.focus();
            return;
        }

        if (!ciphertext) {
            showBruteMessage("Please enter the target ciphertext.", "error");
            ciphertextInput.focus();
            return;
        }

        if (!/^[0-9a-fA-F]{16}$/.test(ciphertext)) {
            showBruteMessage(
                "Ciphertext must contain exactly 16 hexadecimal characters.",
                "error"
            );
            ciphertextInput.focus();
            return;
        }

        if (![8, 12, 16, 20, 24].includes(keyBits)) {
            showBruteMessage("Please select a valid key size.", "error");
            return;
        }

        attackButton.disabled = true;
        attackButton.textContent = "Searching...";

        resetBruteResults();
        showBruteMessage("Running the brute force attack. Please wait...");

        try {
            const response = await fetch("/api/brute-force", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    plaintext: plaintext,
                    ciphertext: ciphertext,
                    key_bits: keyBits
                })
            });

            const data = await response.json();

            if (!response.ok || !data.success) {
                throw new Error(
                    data.error || data.message || "The attack request failed."
                );
            }

            displayAttackResults(data);

            if (data.found) {
                showBruteMessage(
                    "Success! The DES key was recovered.",
                    "success"
                );
            } else {
                showBruteMessage(
                    "No matching key was found in the selected search space.",
                    "error"
                );
            }

            console.log("Brute Force Results:", data);

        } catch (error) {
            console.error("Brute Force Error:", error);

            statusOutput.textContent = "ATTACK FAILED";
            recoveredKeyOutput.value = "Unavailable";

            showBruteMessage(
                error.message || "Unable to connect to the server.",
                "error"
            );

        } finally {
            attackButton.disabled = false;
            attackButton.innerHTML = 'Start Brute Force <span>→</span>';
        }
    });

    console.log("Brute Force Lab JavaScript initialized successfully.");

})();


// ==========================================
// DES SECURITY LAB
// KEY SIZE ANALYSIS
// Benchmark, Results Table & Chart
// ==========================================

const keyAnalysisButton = document.getElementById("keyAnalysisButton");
const keyAnalysisPlaintext = document.getElementById("keyAnalysisPlaintext");
const keyAnalysisMessage = document.getElementById("keyAnalysisMessage");
const keyAnalysisTableBody = document.getElementById("keyAnalysisTableBody");

let keyAnalysisChartInstance = null;


// Format large numbers
function formatKeyAnalysisNumber(value) {
    return Number(value).toLocaleString("en-US");
}


// Format execution time
function formatKeyAnalysisTime(seconds) {
    if (seconds < 1) {
        return (seconds * 1000).toFixed(3) + " ms";
    }

    if (seconds < 60) {
        return seconds.toFixed(3) + " seconds";
    }

    if (seconds < 3600) {
        return (seconds / 60).toFixed(2) + " minutes";
    }

    return (seconds / 3600).toFixed(2) + " hours";
}


// Display benchmark results in the table
function displayKeyAnalysisResults(results) {

    keyAnalysisTableBody.innerHTML = "";

    results.forEach(result => {

        const row = document.createElement("tr");

        const values = [
            `${result.key_bits} bits`,
            formatKeyAnalysisNumber(result.total_keys),
            formatKeyAnalysisNumber(result.sample_size),
            formatKeyAnalysisTime(result.measured_seconds),
            (result.average_time_per_key * 1000).toFixed(4) + " ms",
            formatKeyAnalysisTime(result.estimated_full_search_seconds)
        ];

        values.forEach(value => {
            const cell = document.createElement("td");
            cell.textContent = value;
            row.appendChild(cell);
        });

        keyAnalysisTableBody.appendChild(row);
    });
}


// Draw benchmark chart
function displayKeyAnalysisChart(results) {

    const canvas = document.getElementById("keyAnalysisChart");

    if (!canvas) {
        console.error("Key Analysis chart canvas was not found.");
        return;
    }

    if (typeof Chart === "undefined") {
        console.error("Chart.js is not loaded.");
        return;
    }

    const labels = results.map(result => result.key_bits + " bits");

    const estimatedTimes = results.map(
        result => result.estimated_full_search_seconds
    );

    // Remove previous chart before drawing a new one
    if (keyAnalysisChartInstance) {
        keyAnalysisChartInstance.destroy();
    }

    keyAnalysisChartInstance = new Chart(canvas, {

        type: "line",

        data: {
            labels: labels,

            datasets: [{
                label: "Estimated Full Search Time (seconds)",

                data: estimatedTimes,

                borderWidth: 3,

                tension: 0.3,

                fill: false,

                pointRadius: 5,

                pointHoverRadius: 8
            }]
        },

        options: {

            responsive: true,

            maintainAspectRatio: false,

            interaction: {
                intersect: false,
                mode: "index"
            },

            plugins: {

                legend: {
                    display: true
                },

                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return " Estimated time: " +
                                formatKeyAnalysisTime(context.parsed.y);
                        }
                    }
                }
            },

            scales: {

                y: {
                    type: "logarithmic",

                    title: {
                        display: true,
                        text: "Estimated Time (seconds)"
                    }
                },

                x: {
                    title: {
                        display: true,
                        text: "DES Key Size"
                    }
                }
            }
        }
    });
}


// Run Key Size Analysis
if (keyAnalysisButton) {

    keyAnalysisButton.addEventListener("click", async function() {

        const plaintext = keyAnalysisPlaintext.value;

        // Validate plaintext length in UTF-8 bytes
        const byteLength = new TextEncoder().encode(plaintext).length;

        if (byteLength !== 8) {

            keyAnalysisMessage.textContent =
                "Please enter exactly 8 UTF-8 bytes.";

            keyAnalysisMessage.style.color = "#ef4444";

            return;
        }

        keyAnalysisButton.disabled = true;

        keyAnalysisButton.textContent = "Running Benchmark...";

        keyAnalysisMessage.textContent =
            "Testing 128 key candidates for each key size. Please wait...";

        keyAnalysisMessage.style.color = "#94a3b8";

        try {

            const response = await fetch("/api/key-analysis", {

                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    plaintext: plaintext
                })

            });

            const data = await response.json();

            if (!response.ok || !data.success) {
                throw new Error(data.error || "Key analysis failed.");
            }

            // Display results table
            displayKeyAnalysisResults(data.results);

            // Display chart
            displayKeyAnalysisChart(data.results);

            // Success message
            keyAnalysisMessage.textContent =
                "Analysis completed successfully! " +
                data.results.length +
                " key sizes were tested using " +
                data.sample_size +
                " samples per size.";

            keyAnalysisMessage.style.color = "#22c55e";

        } catch (error) {

            console.error("Key Analysis Error:", error);

            keyAnalysisMessage.textContent =
                "Error: " + error.message;

            keyAnalysisMessage.style.color = "#ef4444";

        } finally {

            keyAnalysisButton.disabled = false;

            keyAnalysisButton.innerHTML =
                'Run Key Size Analysis <span>→</span>';
        }

    });
}

// ==========================================
// DES SECURITY LAB
// WEAK KEY ANALYSIS
// ==========================================

const weakKeyTestButton = document.getElementById("weakKeyTestButton");
const weakKeyMessage = document.getElementById("weakKeyMessage");

const weakTotalTests = document.getElementById("weakTotalTests");
const weakPassedTests = document.getElementById("weakPassedTests");
const weakFailedTests = document.getElementById("weakFailedTests");

const weakKeyOverallStatus = document.getElementById("weakKeyOverallStatus");

const weakKeysResults = document.getElementById("weakKeysResults");
const semiWeakKeysResults = document.getElementById("semiWeakKeysResults");


function createWeakKeyCell(value) {
    const cell = document.createElement("td");
    cell.textContent = value ?? "—";
    return cell;
}


function createVerificationCell(passed) {
    const cell = document.createElement("td");
    const status = document.createElement("span");

    status.textContent = passed ? "PASS" : "FAIL";
    status.className = passed ? "weak-test-pass" : "weak-test-fail";

    cell.appendChild(status);
    return cell;
}


function displayWeakKeyResults(results) {

    // Update summary
    weakTotalTests.textContent = results.total_tests;
    weakPassedTests.textContent = results.total_passed;
    weakFailedTests.textContent = results.total_failed;

    // Overall verification status
    weakKeyOverallStatus.textContent = results.success
        ? "ALL TESTS PASSED"
        : "SOME TESTS FAILED";

    weakKeyOverallStatus.className = results.success
        ? "brute-result weak-overall-pass"
        : "brute-result weak-overall-fail";


    // ======================================
    // DISPLAY WEAK KEYS
    // ======================================

    weakKeysResults.replaceChildren();

    results.weak_keys.forEach((item, index) => {

        const row = document.createElement("tr");

        row.appendChild(createWeakKeyCell(index + 1));
        row.appendChild(createWeakKeyCell(item.key));
        row.appendChild(createWeakKeyCell(item.first_encryption));
        row.appendChild(createWeakKeyCell(item.recovered_block));
        row.appendChild(createVerificationCell(item.passed));

        weakKeysResults.appendChild(row);
    });


    // ======================================
    // DISPLAY SEMI-WEAK KEY PAIRS
    // ======================================

    semiWeakKeysResults.replaceChildren();

    results.semi_weak_pairs.forEach((item, index) => {

        const row = document.createElement("tr");

        row.appendChild(createWeakKeyCell(index + 1));
        row.appendChild(createWeakKeyCell(item.key1));
        row.appendChild(createWeakKeyCell(item.key2));
        row.appendChild(createWeakKeyCell(item.recovered_block));
        row.appendChild(createVerificationCell(item.passed));

        semiWeakKeysResults.appendChild(row);
    });
}


// ==========================================
// RUN WEAK KEY TESTS
// ==========================================

if (weakKeyTestButton) {

    weakKeyTestButton.addEventListener("click", async () => {

        weakKeyTestButton.disabled = true;
        weakKeyTestButton.textContent = "Running Tests...";

        weakKeyMessage.textContent = "Testing DES weak and semi-weak keys...";
        weakKeyMessage.className = "workbench-message";

        try {

            const response = await fetch("/api/weak-keys", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({})
            });

            const results = await response.json();

            if (!response.ok) {
                throw new Error(results.error || "Weak key analysis failed.");
            }

            displayWeakKeyResults(results);

            if (results.success) {
                weakKeyMessage.textContent =
                    "Verification completed successfully: all 10 tests passed.";

                weakKeyMessage.className =
                    "workbench-message success";
            } else {
                weakKeyMessage.textContent =
                    "Verification completed, but some tests failed.";

                weakKeyMessage.className =
                    "workbench-message error";
            }

        } catch (error) {

            weakKeyMessage.textContent =
                "Error: " + error.message;

            weakKeyMessage.className =
                "workbench-message error";

            weakKeyOverallStatus.textContent = "TEST ERROR";
            weakKeyOverallStatus.className =
                "brute-result weak-overall-fail";

        } finally {

            weakKeyTestButton.disabled = false;
            weakKeyTestButton.innerHTML =
                'Run Weak Key Tests <span>→</span>';
        }

    });

}

// ==========================================
// DES SECURITY LAB
// AVALANCHE EFFECT ANALYSIS
// ==========================================

(() => {
    const testButton = document.getElementById("avalancheTestButton");
    const message = document.getElementById("avalancheMessage");

    const elements = {
        originalPlaintext: document.getElementById("avalancheOriginalPlaintext"),
        originalKey: document.getElementById("avalancheOriginalKey"),
        originalCiphertext: document.getElementById("avalancheOriginalCiphertext"),

        blockSize: document.getElementById("avalancheBlockSize"),
        plaintextBits: document.getElementById("avalanchePlaintextBits"),
        keyBits: document.getElementById("avalancheKeyBits"),
        average: document.getElementById("avalancheAverage"),

        modifiedPlaintext: document.getElementById("avalancheModifiedPlaintext"),
        plaintextCiphertext: document.getElementById("avalanchePlaintextCiphertext"),
        plaintextChangedBits: document.getElementById("avalanchePlaintextChangedBits"),
        plaintextPercentage: document.getElementById("avalanchePlaintextPercentage"),

        modifiedKey: document.getElementById("avalancheModifiedKey"),
        keyCiphertext: document.getElementById("avalancheKeyCiphertext"),
        keyChangedBits: document.getElementById("avalancheKeyChangedBits"),
        keyPercentage: document.getElementById("avalancheKeyPercentage"),

        interpretation: document.getElementById("avalancheInterpretation"),
        chart: document.getElementById("avalancheChart")
    };

    let avalancheChartInstance = null;

    if (!testButton || !message) {
        console.error("Avalanche Effect: Required HTML elements are missing.");
        return;
    }

    function showAvalancheMessage(text, type = "") {
        message.textContent = text;
        message.className = "workbench-message";

        if (type) {
            message.classList.add(type);
        }
    }

    function setText(element, value) {
        if (element) {
            element.textContent = value ?? "—";
        }
    }

    function displayAvalancheResults(data) {
        const plaintextTest = data.plaintext_test;
        const keyTest = data.key_test;

        // Original values
        setText(elements.originalPlaintext, data.original_plaintext);
        setText(elements.originalKey, data.original_key);
        setText(elements.originalCiphertext, data.original_ciphertext);

        // Summary
        setText(elements.blockSize, "64 bits");
        setText(
            elements.plaintextBits,
            `${plaintextTest.changed_bits} / 64`
        );
        setText(
            elements.keyBits,
            `${keyTest.changed_bits} / 64`
        );

        const average = (
            (Number(plaintextTest.percentage) +
             Number(keyTest.percentage)) / 2
        );

        setText(elements.average, average.toFixed(2) + "%");

        // Plaintext test
        setText(elements.modifiedPlaintext, plaintextTest.modified_plaintext);
        setText(elements.plaintextCiphertext, plaintextTest.modified_ciphertext);
        setText(
            elements.plaintextChangedBits,
            `${plaintextTest.changed_bits} / 64`
        );
        setText(
            elements.plaintextPercentage,
            Number(plaintextTest.percentage).toFixed(2) + "%"
        );

        // Key test
        setText(elements.modifiedKey, keyTest.modified_key);
        setText(elements.keyCiphertext, keyTest.modified_ciphertext);
        setText(
            elements.keyChangedBits,
            `${keyTest.changed_bits} / 64`
        );
        setText(
            elements.keyPercentage,
            Number(keyTest.percentage).toFixed(2) + "%"
        );

        // Interpretation
        const interpretation =
            `Changing one bit in the plaintext changed ` +
            `${plaintextTest.changed_bits} out of 64 ciphertext bits ` +
            `(${Number(plaintextTest.percentage).toFixed(2)}%). ` +
            `Changing one bit in the key changed ` +
            `${keyTest.changed_bits} out of 64 ciphertext bits ` +
            `(${Number(keyTest.percentage).toFixed(2)}%). ` +
            `These results demonstrate the avalanche effect in DES.`;

        setText(elements.interpretation, interpretation);

        // Chart
        displayAvalancheChart(plaintextTest, keyTest);
    }

    function displayAvalancheChart(plaintextTest, keyTest) {
        if (!elements.chart) {
            console.error("Avalanche chart canvas was not found.");
            return;
        }

        if (typeof Chart === "undefined") {
            console.error("Chart.js is not loaded.");
            return;
        }

        if (avalancheChartInstance) {
            avalancheChartInstance.destroy();
        }

        avalancheChartInstance = new Chart(elements.chart, {
            type: "bar",

            data: {
                labels: [
                    "Plaintext Bit Change",
                    "Key Bit Change"
                ],

                datasets: [{
                    label: "Changed Ciphertext Bits",
                    data: [
                        plaintextTest.changed_bits,
                        keyTest.changed_bits
                    ],
                    borderWidth: 1
                }]
            },

            options: {
                responsive: true,
                maintainAspectRatio: false,

                plugins: {
                    legend: {
                        display: true
                    },

                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const percentage = context.dataIndex === 0
                                    ? plaintextTest.percentage
                                    : keyTest.percentage;

                                return `${context.parsed.y} / 64 bits (${percentage}%)`;
                            }
                        }
                    }
                },

                scales: {
                    y: {
                        beginAtZero: true,
                        min: 0,
                        max: 64,
                        title: {
                            display: true,
                            text: "Changed Bits"
                        }
                    },

                    x: {
                        title: {
                            display: true,
                            text: "Avalanche Test"
                        }
                    }
                }
            }
        });
    }

    // Run Avalanche Tests
    testButton.addEventListener("click", async () => {
        testButton.disabled = true;
        testButton.textContent = "Running Tests...";

        showAvalancheMessage(
            "Running DES avalanche analysis. Please wait..."
        );

        try {
            const response = await fetch("/api/avalanche", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({})
            });

            const data = await response.json();

            if (!response.ok || !data.success) {
                throw new Error(
                    data.error || "Avalanche analysis failed."
                );
            }

            if (!data.plaintext_test || !data.key_test) {
                throw new Error("Incomplete avalanche test results.");
            }

            displayAvalancheResults(data);

            showAvalancheMessage(
                "Avalanche analysis completed successfully!",
                "success"
            );

            console.log("Avalanche Effect Results:", data);

        } catch (error) {
            console.error("Avalanche Effect Error:", error);

            showAvalancheMessage(
                "Error: " + error.message,
                "error"
            );

            setText(
                elements.interpretation,
                "Unable to complete avalanche analysis."
            );

        } finally {
            testButton.disabled = false;
            testButton.innerHTML =
                'Run Avalanche Tests <span>→</span>';
        }
    });

    console.log("Avalanche Effect JavaScript initialized successfully.");

})();

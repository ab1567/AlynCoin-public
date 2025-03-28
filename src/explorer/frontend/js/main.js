const API_BASE = "http://localhost:8080";

// Utility function to display loading spinner
function toggleLoading(show) {
    const loader = document.getElementById('loading');
    if (show) {
        loader.style.display = 'block';
    } else {
        loader.style.display = 'none';
    }
}

// Utility function to handle fetch responses
async function handleFetchResponse(response) {
    if (!response.ok) {
        const errorData = await response.json();
        throw new Error(`Error ${response.status}: ${errorData.message || response.statusText}`);
    }
    return response.json();
}

// ============ Fetch Blockchain Stats ============
async function fetchStats() {
    toggleLoading(true);
    try {
        const response = await fetch(`${API_BASE}/stats`);
        const data = await handleFetchResponse(response);
        document.getElementById('statsOutput').textContent = JSON.stringify(data, null, 2);
    } catch (err) {
        document.getElementById('statsOutput').textContent = `Error fetching stats: ${err.message}`;
        console.error(err);
    } finally {
        toggleLoading(false);
    }
}

// ============ Fetch Block by Hash ============
async function fetchBlock() {
    const hash = document.getElementById('blockHash').value.trim();
    if (!hash) return alert("Please enter a block hash");

    toggleLoading(true);
    try {
        const response = await fetch(`${API_BASE}/block/${hash}`);
        const data = await handleFetchResponse(response);
        document.getElementById('blockOutput').textContent = JSON.stringify(data, null, 2);
    } catch (err) {
        document.getElementById('blockOutput').textContent = `Error fetching block: ${err.message}`;
        console.error(err);
    } finally {
        toggleLoading(false);
    }
}

// ============ Fetch Block by Height ============
async function fetchBlockByHeight() {
    const height = document.getElementById('blockHeight').value.trim();
    if (!height) return alert("Please enter block height");

    toggleLoading(true);
    try {
        const response = await fetch(`${API_BASE}/block/height/${height}`);
        const data = await handleFetchResponse(response);
        document.getElementById('blockHeightOutput').textContent = JSON.stringify(data, null, 2);
    } catch (err) {
        document.getElementById('blockHeightOutput').textContent = `Error fetching block: ${err.message}`;
        console.error(err);
    } finally {
        toggleLoading(false);
    }
}

// ============ Fetch Transaction by Hash ============
async function fetchTransaction() {
    const hash = document.getElementById('txHash').value.trim();
    if (!hash) return alert("Please enter transaction hash");

    toggleLoading(true);
    try {
        const response = await fetch(`${API_BASE}/tx/${hash}`);
        const data = await handleFetchResponse(response);
        document.getElementById('txOutput').textContent = JSON.stringify(data, null, 2);
    } catch (err) {
        document.getElementById('txOutput').textContent = `Error fetching transaction: ${err.message}`;
        console.error(err);
    } finally {
        toggleLoading(false);
    }
}

// ============ Fetch Address Info with Pagination ============
async function fetchAddress() {
    const address = document.getElementById('address').value.trim();
    if (!address) return alert("Please enter address");

    const page = 1;
    const limit = 10;

    toggleLoading(true);
    try {
        const response = await fetch(`${API_BASE}/address/${address}?page=${page}&limit=${limit}`);
        const data = await handleFetchResponse(response);
        document.getElementById('addressOutput').textContent = JSON.stringify(data, null, 2);
    } catch (err) {
        document.getElementById('addressOutput').textContent = `Error fetching address info: ${err.message}`;
        console.error(err);
    } finally {
        toggleLoading(false);
    }
}

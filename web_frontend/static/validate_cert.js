async function validateCertificate(certPEM, keyPEM) {
    try {
        const response = await fetch('/api/settings/ca-certificate/validate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ca_certificate: certPEM,
                ca_private_key: keyPEM,
            }),
        });

        if (response.ok) {
            return { valid: true };
        }

        let error = `Validation failed (HTTP ${response.status})`;
        try {
            const result = await response.json();
            if (result && result.error) {
                error = result.error;
            }
        } catch (_) {
            
        }
        return { valid: false, error };
    } catch (e) {
        return { valid: false, error: e && e.message ? e.message : String(e) };
    }
}

export { validateCertificate };

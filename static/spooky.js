document.addEventListener('DOMContentLoaded', function() {
    const rangeButton = document.querySelector('button[onclick="createRange();"]');
    if (rangeButton) {
        rangeButton.addEventListener('click', createRange);
    }
});


function setTemplate() {
    const vmid = document.getElementById('template-vmid').value;
    const club = (document.getElementById('template-club').value || '').trim().toUpperCase() || 'TEST';
    const status = document.getElementById('set-template-status');

    if (!vmid) {
        status.textContent = 'Please select a template.';
        return;
    }

    status.textContent = 'Saving…';

    fetch('/admin/set-template', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vmid: parseInt(vmid, 10), club }),
    })
    .then(function(res) { return res.json().then(function(d) { return { ok: res.ok, data: d }; }); })
    .then(function(r) {
        if (r.ok) {
            status.textContent = 'Active: ' + r.data.label + ' | namespace: ' + r.data.club + '/username-range';
        } else {
            status.textContent = 'Error: ' + (r.data.error || 'unknown');
        }
    })
    .catch(function(e) {
        status.textContent = 'Network error: ' + e;
    });
}


function ensureUsers() {
    const usernames = document.getElementById('usernames').value;

    if (usernames.trim() === '') {
        alert('Please enter usernames');
        return;
    }

    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/ensure', true);
    xhr.setRequestHeader('Content-Type', 'application/json');

    xhr.onload = function() {
        if (xhr.status === 200) {
            document.getElementById('usernames').value = '';
            alert('All users validated in AD realm: ' + xhr.responseText);
        } else if (xhr.status === 400) {
            alert('User validation failed: ' + xhr.responseText);
        } else {
            alert('An error occurred during validation');
        }
    };

    xhr.send(JSON.stringify({ usernames }));
}


function createRange() {
    const usernames = document.getElementById('rusernames').value;
    const vmids = document.getElementById('vmids').value;

    if (usernames.trim() === '' || vmids.trim() === '') {
        document.getElementById('rusernames').value = '';
        document.getElementById('vmids').value = '';
        alert('Please enter usernames and vmids');
        return;
    }

    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/range', true);
    xhr.setRequestHeader('Content-Type', 'application/json');

    xhr.onload = function() {
        if (xhr.status === 200) {
            document.getElementById('rusernames').value = '';
            document.getElementById('vmids').value = '';
            alert('Cloning done');
        } else {
            alert('Error: ' + xhr.status + ' — ' + xhr.responseText);
        }
    };

    xhr.send(JSON.stringify({ usernames, vmids }));
}

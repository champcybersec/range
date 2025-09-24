document.addEventListener('DOMContentLoaded', function() {
    const rangeButton = document.querySelector('button[onclick="createRange();"]');
    rangeButton.addEventListener('click', createRange);
});


function ensureUsers() {

    // Get the value of the usernames text field
    const usernames = document.getElementById('usernames').value;

    // Check if the value of usernames is blank
    if (usernames.trim() === '') {
        alert('Please enter usernames');
        return;
    }

    // Create a new XMLHttpRequest object
    const xhr = new XMLHttpRequest();

    // Set up the request
    xhr.open('POST', '/ensure', true);
    xhr.setRequestHeader('Content-Type', 'application/json');

    // Set up the callback function
    xhr.onload = function() {
        if (xhr.status === 200) {
            // Request was successful
            console.log(xhr.responseText);
            document.getElementById('usernames').value = '';
            alert('All users validated in AD realm: ' + xhr.responseText);
        } else if (xhr.status === 400) {
            // Validation failed
            console.error('Validation Error:', xhr.responseText);
            alert('User validation failed: ' + xhr.responseText);
        } else {
            // Other error
            console.error('Error:', xhr.status);
            alert('An error occurred during validation');
        }
    };

    // Send the request
    xhr.send(JSON.stringify({ usernames }));
}

function createRange() {
    alert('Creating range');
    // Get the value of the usernames text field
    const usernames = document.getElementById('rusernames').value;
    const vmids = document.getElementById('vmids').value;

    // Check if the value of usernames or vmids is blank
    if (usernames.trim() === '' || vmids.trim() === '') {
        document.getElementById('rusernames').value = '';
        document.getElementById('vmids').value = '';
        alert('Please enter usernames and vmids');
        return;
    }

    // Create a new XMLHttpRequest object
    const xhr = new XMLHttpRequest();

    // Set up the request
    xhr.open('POST', '/range', true);
    xhr.setRequestHeader('Content-Type', 'application/json');

    // Set up the callback function
    xhr.onload = function() {
        if (xhr.status === 200) {
            // Request was successful
            console.log(xhr.responseText);
            document.getElementById('rusernames').value = '';
            document.getElementById('vmids').value = '';
            alert('Cloning done');
        } else {
            // Request failed
            console.error('Error:', xhr.status);
        }
    };

    // Send the request
    xhr.send(JSON.stringify({ usernames, vmids }));
}
document.addEventListener('DOMContentLoaded', function () {
  const form = document.getElementById('login-form');
  if (!form) return;

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    const role = document.getElementById('role')?.value || '';
    const userid = document.getElementById('userid')?.value.trim() || '';
    const password = document.querySelector('input[type=password]')?.value || '';

    if (!role) { alert('Please select a role.'); return; }
    if (!userid) { alert('Please enter your ID.'); return; }
    if (!password) { alert('Please enter your password.'); return; }

    // Call backend login endpoint with JWT
    fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userid, password, role })
    })
      .then(resp => {
        if (!resp.ok) throw new Error('Invalid credentials');
        return resp.json();
      })
      .then(data => {
        // Store token in localStorage
        localStorage.setItem('token', data.access_token);
        localStorage.setItem('user_id', data.user_id);
        localStorage.setItem('role', data.role);
        // Redirect to dashboard
        window.location.href = 'Dashboard.html';
      })
      .catch(err => {
        alert('Login failed: ' + err.message);
      });
  });
});

const role = document.getElementById("role");
const label = document.getElementById("label-id");
const userid = document.getElementById("userid");

role.addEventListener("change", function () {
    const selectedRole = role.value;

    if (selectedRole === "Govt") {
        label.textContent = "Government ID";
        userid.placeholder = "Enter Government ID";
    } 
    else if (selectedRole === "Accountant") {
        label.textContent = "Accountant ID";
        userid.placeholder = "Enter Accountant ID";
    } 
    else {
        label.textContent = "User ID";
        userid.placeholder = "Enter GSTIN / User ID";
    }
});

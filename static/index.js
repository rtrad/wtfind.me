/**
 * Created by nikhil on 4/22/2017.
 */
var txtsignInUsername = document.getElementById('emailAddress');
var txtregisterUsername = document.getElementById('emailAddress2');
var txtsignInPassword = document.getElementById('password');
var txtregisterPassword = document.getElementById('password2');
var txtregisterPassword2 = document.getElementById('password3');
var currentUser = JSON.parse(sessionStorage.getItem('currentUser'));
var email = document.getElementById('email');
var phone = document.getElementById('phone');
var name = document.getElementById('fullName');

function User(username, password, email, phone, name) {
    this.username = username;
    this.password = password;
    this.email = email;
    this.phone = phone;
    this.name = name;
}

function verifyPass() {
    if (txtregisterPassword.value.length > 3) {
        if (txtregisterPassword.value === txtregisterPassword2.value) {
            return true;
        } else {
            document.getElementById('retypePass').innerHTML = "Repeat Password - Passwords do not match!";
            document.getElementById('retypePass').focus();
        }
    } else {
        document.getElementById('passRegister').innerHTML = "Password - Password too short!";
        document.getElementById('passRegister').focus();
    }
}

$('#register').click(function(){
    if (verifyPass()) {
        var username = txtregisterUsername.value;
        var pass = txtregisterPassword.value;
        var email = email.value;
        var phone = phone.value;
        var name = name.value;
        currentUser = new User(username, pass, email, phone, name);
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "/register", true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.send(JSON.stringify(currentUser));
        xhr.onload = function () {
            if (xhr.status == 200)
                window.location.href = '/home';
            else 
                alert('Registration failed:', xhr.response);
        }
        console.log("Created you" + currentUser.username);
    } else {
        console.log("Passwords do not match!");
    }
});
$('#login').click(function(){
    var username = txtsignInUsername.value;
    var pass = txtsignInPassword.value;
    currentUser = new User(username, pass, null, null, null);
    var xhr = new XMLHttpRequest();
    xhr.open("POST", "/login", true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send(JSON.stringify(currentUser));
    xhr.onload = function () {
        if (xhr.status == 200)
                window.location.href = '/home';
        else 
            alert('Login failed');
    }
});

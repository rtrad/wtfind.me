/**
 * Created by nikhil on 4/22/2017.
 */
var txtsignInUsername = document.getElementById('emailAddress');
var txtregisterUsername = document.getElementById('emailAddress2');
var txtsignInPassword = document.getElementById('password');
var txtregisterPassword = document.getElementById('password2');
var txtregisterPassword2 = document.getElementById('password3');
var currentUser = JSON.parse(sessionStorage.getItem('currentUser'));

function User(username, password) {
    this.username = username;
    this.pass = password;
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
        currentUser = new User(username, pass);
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "/register", true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.send({
            username: username,
            password: pass
        });
        console.log("Created you" + currentUser.username);
    } else {
        console.log("Passwords do not match!");
    }
});
$('#login').click(function(){
    var username = txtsignInUsername.value;
    var pass = txtsignInPassword.value;
    currentUser = new User(username, pass);
    var xhr = new XMLHttpRequest();
    xhr.open("POST", "/login", true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send({
        username: username,
        password: pass
    });
    console.log("Logged you" + currentUser.username);
     console.log("Passwords do not match!");
});

function checkPasswordMatch() {
	var password = $('#txtNewPassword').val();
	var confirmPassword = $('#txtConfirmPassword').val();

	if (password != confirmPassword) {
		$('#divCheckPasswordMatch').html('Passwords do not match!');
		document.getElementById('confirm-btn').setAttribute('disabled',true);
	} else {
		$('#divCheckPasswordMatch').html('Passwords match.');
    document.getElementById('confirm-btn').removeAttribute('disabled')
	}
}
$(document).ready(function () {
	$('#txtNewPassword, #txtConfirmPassword').keyup(checkPasswordMatch);
});

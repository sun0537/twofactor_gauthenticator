if (window.rcmail) {
  rcmail.addEventListener('init', function() {
	// remove the user/password/... input from login
    $('form > table > tbody > tr').each(function(){
    	$(this).remove();
    });
	
    // change task & action
    $('form').attr('action', './');
    $('input[name=_task]').attr('value', 'mail');
    $('input[name=_action]').attr('value', '');

	//determine twofactor field type based on config settings
	if(rcmail.env.twofactor_formfield_as_password)
		var twoFactorCodeFieldType = 'password';
	else
		var twoFactorCodeFieldType = 'text';
	
	//twofactor input form
    var text = '';
    text += '<tr class="form-group row">';
    text += '<td class="input input-group input-group-lg">';
    text += '<span class="input-group-prepend"><i class="input-group-text icon key"></i></span>';
    text += '<input name="_code_2FA" id="2FA_code" size="40" maxlength="10" class="form-control" autocapitalize="off" autocomplete="off" type="' + twoFactorCodeFieldType + '" placeholder="Code">';
    text += '</td>';
    text += '</tr>';

    // remember option
    if(rcmail.env.allow_save_device_30days){
		text += '<tr>';
		text += '<td class="title" colspan="2"><input type="checkbox" id="remember_2FA" name="_remember_2FA" value="yes"/><label for="remember_2FA">'+rcmail.gettext('dont_ask_me_30days', 'twofactor_gauthenticator')+'</label></td>';
		text += '</tr>';
	}

    // create textbox
    $('form > table > tbody:last').append(text);

    // focus
    $('#2FA_code').focus();
    
  });

};

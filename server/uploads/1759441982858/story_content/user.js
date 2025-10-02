window.InitUserScripts = function()
{
var player = GetPlayer();
var object = player.object;
var once = player.once;
var addToTimeline = player.addToTimeline;
var setVar = player.SetVar;
var getVar = player.GetVar;
var update = player.update;
var pointerX = player.pointerX;
var pointerY = player.pointerY;
var showPointer = player.showPointer;
var hidePointer = player.hidePointer;
var slideWidth = player.slideWidth;
var slideHeight = player.slideHeight;
window.Script1 = function()
{
  var currentDate = new Date()
var day = currentDate.getDate()
var month = currentDate.getMonth() + 1
var year = currentDate.getFullYear();
var player = GetPlayer();
var newName = month + "/" + day + "/" +year
player.SetVar("DateValue", newName);


}

window.Script2 = function()
{
  // Name of the certificate html file
var certFilename = 'certificate.html';

// HTMLCollection of elements of type iFrame
var iframeElements = document.getElementsByTagName("iframe");

// Iterate over the iFrameElements HTMLCollection
for(var i = 0; i < iframeElements.length; i++){
    /* If src of current iFrame element equals the filename set in variable
	** certFilename call the generatePDF() function.
	*/
    var src = iframeElements[i].getAttribute('src');
	if (src.indexOf(certFilename) !=-1) {
		iframeElements[i].contentWindow.generatePDF();
	}
}
}

};

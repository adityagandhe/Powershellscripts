

var element =document.createElement('link'); 
element.setAttribute("rel","stylesheet") ;
element.setAttribute("type","text/css") ;
element.setAttribute("href","https://yavatmal3.sharepoint.com/sites/RND/SiteAssets/CSS/BannerScript.css")
document.getElementsByTagName("head")[0].appendChild(element);
SP.SOD.executeOrDelayUntilEventNotified(function () {
	
	SP.SOD.executeFunc('sp.js','SP.ClientContext',sharePointReady);
},"sp.bodyloaded");
var collListItem ="";
var collListBannerItem=""
var currentUrl="";
var siteUrl ="https://yavatmal3.sharepoint.com/sites/RND";
function sharePointReady(){

	//alert("ready");
getBanner();
getRedirection();	
	
}
function getBanner(){
	collListBannerItem ="";
	    // executed when SP load completes
	SP.SOD.executeOrDelayUntilEventNotified(function () {currentUrl =_spPageContextInfo.webAbsoluteUrl ;
var clientContext = new SP.ClientContext(siteUrl);
    var currentUrl =_spPageContextInfo.webAbsoluteUrl;
    var oList = clientContext.get_web().get_lists().getByTitle('BannerSolution');
        
    var camlQuery = new SP.CamlQuery();
	    camlQuery.set_viewXml('<View><Query><Where> <And><Eq> <FieldRef Name=\'DisplayBanner\' /><Value Type=\'Boolean\'>1</Value></Eq><Eq><FieldRef Name=\'Title\' /><Value Type=\'Text\'>'+ currentUrl +'</Value></Eq></And></Where></Query></View>');
    
    this.collListBannerItem = oList.getItems(camlQuery);
        
    clientContext.load(collListBannerItem);
        
    clientContext.executeQueryAsync(Function.createDelegate(this, this.onBanneryQuerySucceeded), Function.createDelegate(this, this.onBannerQueryQueryFailed));	
	},"sp.bodyloaded");
	
	
}


function onBanneryQuerySucceeded(sender, args)
{
	
		 var messsage = '';
         var theme="";
		 var linkurl ="";
var itemCount = collListBannerItem.get_count();
 //alert("Count"+itemCount);
 if(itemCount >0)
 {
    for (var i = 0; i <= itemCount - 1; i++) {
        var oListItem = collListBannerItem.itemAt(i);
        messsage =oListItem.get_item('Message');
		theme =oListItem.get_item('Status');
		linkurl=oListItem.get_item('Link');
    }
	//alert(theme,messsage) ;
	
	
	var a = document.createElement('a');  
                  
                // Create the text node for anchor element. 
             var link = document.createTextNode("Here"); 
                  
                // Append the text node to anchor element. 
                a.appendChild(link);  
                  
                // Set the title. 
                a.title = "Here";  
                  
                // Set the href property. 
                a.href = linkurl ;
                  a.id="link"
                // Append the anchor element to the body. 
                  
    var element = document.createElement("div");
element.appendChild(document.createTextNode(messsage));

element.appendChild(a)
//alert("inner",element);
if(theme =="Planned")
{
element.id = 'Planned'
}
if(theme =="InProgress")
{
element.id = 'InProgress'
}
if(theme =="Delta")
{
element.id = 'Delta'
}
if(theme =="Hypercare")
{
element.id = 'Hypercare'
}
if(theme =="UAT")
{
element.id = 'UAT'
}
console.log(element);
var originalElement = document.getElementById('s4-workspace')
originalElement.prepend(element).appendChild(a)
 }
 else{
	
 }
}
function onBannerQueryQueryFailed (sender, args)
{
	 console.log('Failed' + args.get_message() + '\n' + args.get_stackTrace());
}
function getRedirection(){

	
	collListItem ="";
    // executed when SP load completes
	SP.SOD.executeOrDelayUntilEventNotified(function () {currentUrl =_spPageContextInfo.webAbsoluteUrl ;
var clientContext = new SP.ClientContext(siteUrl);

    var oList = clientContext.get_web().get_lists().getByTitle('BannerSolution');
            var currentUrl =_spPageContextInfo.webAbsoluteUrl;
    var camlQuery = new SP.CamlQuery();
	    camlQuery.set_viewXml('<View><Query><Where> <And><Eq> <FieldRef Name=\'SetRedirection\' /><Value Type=\'Boolean\'>1</Value></Eq><Eq><FieldRef Name=\'Title\' /><Value Type=\'Text\'>'+ currentUrl +'</Value></Eq></And></Where></Query></View>');
    
    this.collListItem = oList.getItems(camlQuery);
        
    clientContext.load(collListItem);
        
    clientContext.executeQueryAsync(Function.createDelegate(this, this.onRedirectionQuerySucceeded), Function.createDelegate(this, this.onRedirectionQueryFailed));	
	},"sp.bodyloaded");
	

}


function onRedirectionQuerySucceeded(sender, args)
{
	
		 var target = '';

var itemCount = collListItem.get_count();
 //alert("Count"+itemCount);
 if(itemCount >0)
 {
    for (var i = 0; i <= itemCount - 1; i++) {
        var oListItem = collListItem.itemAt(i);
        target =oListItem.get_item('Target');
    }
	window.location.href = target;
 }
 else{
	
 }
}
function onRedirectionQueryFailed (sender, args)
{
	 console.log('Failed' + args.get_message() + '\n' + args.get_stackTrace());
}
function OldBanner()
{



}
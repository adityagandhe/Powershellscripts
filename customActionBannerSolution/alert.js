alert("working");

SP.SOD.executeOrDelayUntilEventNotified(function () {
	var a = document.createElement('a');  
                  
                // Create the text node for anchor element. 
                var link = document.createTextNode("This is link"); 
                  
                // Append the text node to anchor element. 
                a.appendChild(link);  
                  
                // Set the title. 
                a.title = "This is Link";  
                  
                // Set the href property. 
                a.href = "https://www.geeksforgeeks.org";  
                  a.id="link"
                // Append the anchor element to the body. 
                  
    var element = document.createElement("div");
element.appendChild(document.createTextNode('The man who mistook his wife for a hat in test'));
element.appendChild(a)
alert("inner",element);
element.id = 'divcss'
console.log(element);
var originalElement = document.getElementById('s4-workspace')
originalElement.prepend(element).appendChild(a);
}, "sp.bodyloaded");
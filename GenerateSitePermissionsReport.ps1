

#Block to connect the Root Site


Connect-PnPOnline -Url "https://yavatmal3.sharepoint.com/sites/RND" 
$Web = Get-PnPWeb
$permissions =Get-PnPUser -WithRightsAssigned 
$listColl=Get-PnPList -Web $web -Includes HasUniqueRoleAssignments     
    foreach($list in $listColl)  
    {    
        if($list.HasUniqueRoleAssignments)  
        {  
            write-host -ForegroundColor Yellow $list.Title " has unique permissions"  
        }        
    }     

#Block To connect the SubSite





#Block to get list Permissions






#Block to get list item permissions
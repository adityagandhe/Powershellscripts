   
   $VALUE1 ="azserfdr,ioiii,iiijjlllllllllllllllll,azserfdr,ioiii,iiijjlllllllllllllllll,azserfdr,ioiii,iiijjlllllllllllllllll,azserfdr,ioiii,iiijjlllllllllllllllll,azserfdr,ioiii,iiijjlllllllllllllllll,azserfdr,ioiii,iiijjlllllllllllllllll,azserfdr,ioiii,iiijjlllllllllllllllll,azserfdr,ioiii,iiijjlllllllllllllllllazserfdr,ioiii,iiijjlllllllllllllllll,azserfdr,ioiii,iiijjlllllllllllllllll,azserfdr,ioiii,iiijjlllllllllllllllll,azserfdr,ioiii,iiijjlllllllllllllllll,azserfdr,ioiii,iiijjlllllllllllllllll,azserfdr,ioiii,iiijjlllllllllllllllll,azserfdr,ioiii,iiijjlllllllllllllllll,azserfdr,ioiii,iiijjlllllllllllllllll"
      $VALUE2 ="azserfdr,ioiii,iiijjlllllllllllllllll,azserfdr,ioiii,iiijjlllllllllllllllll,azserfdr,ioiii,iiijjlllllllllllllllll,azserfdr,ioiii,iiijjlllllllllllllllll,azserfdr,ioiii,iiijjlllllllllllllllll,azserfdr,ioiii,iiijjlllllllllllllllll,azserfdr,ioiii,iiijjlllllllllllllllll,azserfdr,ioiii,iiijjlllllllllllllllllazserfdr,ioiii,iiijjlllllllllllllllll,azserfdr,ioiii,iiijjlllllllllllllllll,azserfdr,ioiii,iiijjlllllllllllllllll,azserfdr,ioiii,iiijjlllllllllllllllll,azserfdr,ioiii,iiijjlllllllllllllllll,azserfdr,ioiii,iiijjlllllllllllllllll,azserfdr,ioiii,iiijjlllllllllllllllll,azserfdr,ioiii,iiijjlllllllllllllllll,1"
   $props1 = @{'Key' = $VALUE1 }
      $props2 = @{'Key' = $VALUE2 }

                        $itemVALUE1 = New-Object -TypeName PSObject -Property $props1
                        $itemVALUE2 = New-Object -TypeName PSObject -Property $props2

                        Compare-Object $itemVALUE1  $itemVALUE2 -Property "Key" | Where-Object { $_.SideIndicator -eq '<=' }
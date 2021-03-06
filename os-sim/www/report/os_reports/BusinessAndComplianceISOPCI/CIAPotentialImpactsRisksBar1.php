<?php
/**
*
* License:
*
* Copyright (c) 2003-2006 ossim.net
* Copyright (c) 2007-2013 AlienVault
* All rights reserved.
*
* This package is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; version 2 dated June, 1991.
* You may not use, modify or distribute this program under any other version
* of the GNU General Public License.
*
* This package is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this package; if not, write to the Free Software
* Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
* MA  02110-1301  USA
*
*
* On Debian GNU/Linux systems, the complete text of the GNU General
* Public License can be found in `/usr/share/common-licenses/GPL-2'.
*
* Otherwise you can read it here: http://www.gnu.org/licenses/gpl-2.0.txt
*
*/


require_once 'av_init.php';
Session::logcheck("report-menu", "ReportsReportServer");

$date_from = (GET('date_from') != "") ? GET('date_from') : strftime("%Y-%m-%d", time() - (24 * 60 * 60 * 30));
$date_to   = (GET('date_to') != "")   ? GET('date_to')   : strftime("%Y-%m-%d", time());

ossim_valid($date_from, OSS_DATE, 'illegal:' . _('Date From'));
ossim_valid($date_to, OSS_DATE, 'illegal:' . _('Date To'));
if (ossim_error())
{
    die(ossim_error());
}

$sql_year  = "STR_TO_DATE( CONCAT( a.year, '-', a.month, '-', a.day ) , '%Y-%m-%d' ) >= '$date_from' AND STR_TO_DATE( CONCAT( a.year, '-', a.month, '-', a.day ) , '%Y-%m-%d' ) <= '$date_to'";

require_once ('ossim_db.inc');
$db   = new ossim_db();
$conn = $db->connect();
$user = Session::get_session_user();

$conn->Execute('use datawarehouse');
$sql="SELECT * FROM ( SELECT * FROM
(select s.service as service, 'Availability' as category, sum(c.D) as volume from datawarehouse.ssi_user a,
datawarehouse.category c, datawarehouse.ip2service s
where c.D <> '0' and a.sid=c.sid and a.destination=s.dest_ip and ".$sql_year." AND a.user='".$user."' GROUP BY
2) as imp_D
UNION SELECT * FROM
(select s.service as service, 'Integrity' as category, sum(c.I) as volume from datawarehouse.ssi_user a,
datawarehouse.category c, datawarehouse.ip2service s
where c.I <> '0' and a.sid=c.sid and a.destination=s.dest_ip and ".$sql_year." AND a.user='".$user."' GROUP BY 2)
as imp_I
UNION SELECT * FROM
(select s.service as service, 'Confidentiality' as category, sum(c.C) as volume from datawarehouse.ssi_user a,
datawarehouse.category c, datawarehouse.ip2service s
where c.C <> '0' and a.sid=c.sid and a.destination=s.dest_ip and ".$sql_year." AND a.user='".$user."' GROUP BY
2) as imp_C
) AS allalarms;";

$rs = $conn->Execute($sql);

if (!$rs) {
    print $conn->ErrorMsg();
    return;
}

// test perms for source or destination ips
$var=array();
while (!$rs->EOF) {
    $var1 = $rs->fields["category"];
    $var2 = $rs->fields["volume"];
    $var3 = $rs->fields["service"];
    $var[]=array(
        'var1'=>$var1,
        'var2'=>$var2,
        'var3'=>$var3
    );
    $rs->MoveNext();
}
$db->close($conn);

// define colors
define('COLOR1','#D6302C');
define('COLOR2','#3933FC');
define('COLOR3','green');
define('COLOR4','yellow');
define('COLOR5','pink');
define('COLOR6','#40E0D0');
define('COLOR7','#00008B');
define('COLOR8','#800080');
define('COLOR9','#FFA500');
define('COLOR10','#A52A2A');
define('COLOR11','#228B22');
define('COLOR12','#D3D3D3');
//
// creamos dos grupos y a?adimos sus valores
$data=array();
if(count($var)==0){
    $var_port[]=array(
        'var1'=>'',
        'var2'=>0
    );
}
foreach ($var as $value){
    $data['title'][]=$value['var1'];
    $data['value'][]=$value['var2'];
}
//
require_once ('ossim_conf.inc');
$conf = $GLOBALS["CONF"];
$jpgraph = $conf->get_conf("jpgraph_path");
require_once "$jpgraph/jpgraph.php";
require_once "$jpgraph/jpgraph_bar.php";
// Setup the graph.
$graph = new Graph(600, 250, "auto");
$graph->SetScale("textlin");
$graph->Set90AndMargin(150,10,20,0);

$graph->SetMarginColor("#fafafa");

$graph->xaxis->SetTickLabels($data['title']);
$graph->SetColor("#fafafa");
$graph->SetFrame(true,'#fafafa',0);


// Create the bar plots
$b1plot = new BarPlot($data['value']);
// color@transparencia
$b1plot->SetFillColor(array(COLOR1."@0.5",COLOR2."@0.5",COLOR3."@0.5",COLOR4."@0.5",COLOR5."@0.5",COLOR6."@0.5",COLOR7."@0.5",COLOR8."@0.5",COLOR9."@0.5",COLOR10."@0.5",COLOR11."@0.5",COLOR12."@0.5"));
//
$b1plot->SetShadow(array(COLOR1."@0.7",COLOR2."@0.7",COLOR3."@0.7",COLOR4."@0.7",COLOR5."@0.7",COLOR6."@0.7",COLOR7."@0.7",COLOR8."@0.7",COLOR9."@0.7",COLOR10."@0.7",COLOR11."@0.7",COLOR12."@0.7"),5,5);
$b1plot->SetColor(array(COLOR1."@1",COLOR2."@1",COLOR3."@1",COLOR4."@1",COLOR5."@1",COLOR6."@1",COLOR7."@1",COLOR8."@1",COLOR9."@1",COLOR10."@1",COLOR11."@1",COLOR12."@1"));
//
$graph->Add($b1plot);
// Finally send the graph to the browser
$graph->Stroke();
unset($graph);
?>
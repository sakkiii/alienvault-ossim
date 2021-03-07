<?php
/**
* omp.inc
*
* File omp.inc is used to:
*   - To manage OMP protocol
*
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
* @package    ossim-framework\Vulnerabilities
* @autor      AlienVault INC
* @license    http://www.gnu.org/licenses/gpl-2.0.txt
* @copyright  2003-2006 ossim.net
* @copyright  2007-2013 AlienVault
* @link       https://www.alienvault.com/
*/

class Omp
{
    private $binary_location;


    private $latest_binary_location;


    private $ip;


    private $port;


    private $user;


    private $password;


    private $db;


    private $conn;


    private $error_message;

    /**
     * @codeCoverageIgnore
     */
    public static function factory($host = '', $port = '', $user = '', $pass = '', $path = '') {
        return new Omp($host, $port, $user, $pass, $path);
    }

    public function __construct($host = '', $port = '', $user = '', $pass = '', $path = '') {

        require_once __DIR__ . "/../ossim_db.inc";
        $this->db = new ossim_db();
        $this->conn = $this->db->connect();

        $this->latest_binary_location = "/usr/bin/omp";  // ** to use standard input **
   
        if ($path=="" || $host=="" || $port=="" || $user=="" || $pass=="") {
            $conf = $GLOBALS["CONF"];
        }
        
        if($path=="") { $this->binary_location = $conf->get_conf("nessus_path", FALSE); }
        else { $this->binary_location = $path; }
        
        if($host=="") { $this->ip = $conf->get_conf("nessus_host", FALSE); }
        else { $this->ip = $host; }
        
        if($port=="") { $this->port = $conf->get_conf("nessus_port", FALSE); }
        else { $this->port = $port; }
        
        if($user=="") { $this->user = $conf->get_conf("nessus_user", FALSE); }
        else { $this->user = $user; }
        
        if($pass=="") { $this->password = $conf->get_conf("nessus_pass", FALSE); }
        else { $this->password = $pass; }

        $this->user     = str_replace("'","'\"'\"'",$this->user);
        $this->password = str_replace("'","'\"'\"'",$this->password);
        
        $this->error_message = "";
    }


    function __destruct(){
        $this->db->close($this->conn);
    }


    /*****************************************************
     *
     * Open VAS user-related methods.
     *  - get_roles
     *  - get_users
     *  - get_omp_user
     *  - get_error_msg
     *  - create_user
     *  - update_user
     *  - update_user_pass
     *
     *****************************************************/

    public function get_error_msg(){
        return $this->error_message;
    }


    public function get_roles() {
        $roles = array();

        $xml = $this->execute_command('<get_roles />');
        if ($xml === FALSE) {
            return 0;
        }

        foreach ($xml->role as $role) {
            $roles[(string)$role->name] = (string)$role['id'];
        }

        return $roles;
    }


    public function get_users() {
        $users = array();

        $xml = $this->execute_command('<get_users />');
        if ($xml === FALSE) {
            return $users;
        }

        foreach ($xml->user as $user) {
            $user_data = array();
            
            $user_data['user_id'] = (string)$user['id'];
            $user_data['role_id'] = (string)$user->role['id'];
            $user_data['role_name'] = (string)$user->role->name;

            $users[(string)$user->name] = $user_data;
        }

        return $users;
    }


    public function get_omp_user_by_name($username) {
        $users = array_keys($this->get_users());

        foreach ($users as $user) {
            if ($user === $username) { return $user; }
        }

        return "";
    }


    public function create_user($username, $password) {
        $roles = $this->get_roles();

        if ( empty($roles) ) {
            return FALSE;
        }

        $cmd = "<create_user><name>%s</name><password>%s</password><role id=\"%s\"/></create_user>";

        $xml = $this->execute_command(sprintf($cmd, $username, $password, $roles['Admin']));

        if ($xml === FALSE) {
            return FALSE; 
        }

        return TRUE;
    }


    public function update_user($old_user, $new_user, $password) {
        $cmd="<modify_user><name>%s</name><new_name>%s</new_name><password>%s</password></modify_user>";

        $xml = $this->execute_command(sprintf($cmd, $old_user, $new_user, $password));
        // Try to update pass if such username already exists;
        if ($xml === FALSE) {
            return $this->update_user_pass($new_user, $password);
        }

        return TRUE;        
    }


    public function update_user_pass($username, $password) {
        $cmd="<modify_user><name>%s</name><password>%s</password></modify_user>";

        $xml = $this->execute_command(sprintf($cmd, $username, $password));
        
        if ($xml === FALSE) {
            return FALSE;
        }

        return TRUE;

    }

    
    public function execute_command ($command, $sinput=TRUE, $tmp_name=NULL) {

        $binary_location        = $this->binary_location;
        $latest_binary_location = $this->latest_binary_location;
        $ip                     = $this->ip;
        $port                   = $this->port;
        $user                   = $this->user;
        $password               = $this->password;
        if (is_null($tmp_name))
        {
            $tmpfile            = "/usr/share/ossim/www/tmp/omp".substr(preg_replace("/\D/", "", uniqid(md5(rand()), true)),0,15).".xml";;
        }
        else
        {
            $tmpfile            = "/usr/share/ossim/www/tmp/".$tmp_name;
        }

        $file_omp_command = "";
        
        if($sinput && file_exists($latest_binary_location)) { // use standard input stream
            $file_omp_command = "/usr/share/ossim/www/tmp/omp_command".substr(preg_replace("/\D/", "", uniqid(md5(rand()), true)),0,15).".xml";
            
            file_put_contents($file_omp_command, $command);
            
            $ecommand = "? -h ? -p ? -u ? -w ? -iX - < ? > ? 2>&1";
            $params   = array($latest_binary_location, $ip, $port, $user, $password, $file_omp_command, $tmpfile);
        }
        else {
            $ecommand = "? -h ? -p ? -u ? -w ? -iX ? > ? 2>&1";
            $params   = array($binary_location, $ip, $port, $user, $password, $command, $tmpfile);
        }
        
        Util::execute_command($ecommand, $params); // execute OMP command
        
        if($sinput && file_exists($file_omp_command)) {
            unlink($file_omp_command);
        }
        
        if(!file_exists($tmpfile)) {
          return FALSE;
        }
        else {
            $data = file_get_contents($tmpfile);
            unlink($tmpfile);
        }
        $xml = @simplexml_load_string($data);
        
        if (!is_object($xml)) {
            $this->error_message = trim($data);
            return FALSE;
        }
        else if (!preg_match("/^20.*/",$xml->attributes()->status)) {
            //echo _("Error: status = ".$xml->attributes()->status.", status_text = ".$xml->attributes()->status_text." ($tmpfile)")."<br>";
            $this->error_message = trim($xml->attributes()->status_text);
            return FALSE;
        }

        return $xml;
    }


    public function get_config_id_by_sid($sid) {
 
        $config_id = "";
        
        $this->conn->SetFetchMode(ADODB_FETCH_BOTH);
        
        $result = $this->conn->Execute("SELECT name, owner FROM vuln_nessus_settings WHERE id=$sid");
        $cname = $result->fields["name"];
        $cuser = $result->fields["owner"];

        $xml = $this->execute_command ("<get_configs />");

        if ($xml === FALSE) { return $config_id; }
        
        foreach ($xml->config as $config) {
            if( ($cname ==(string)$config->name) && ($cuser==(string)$config->comment) ){
                $config_id = (string)$config->attributes()->id;
            }
        }
        return $config_id;
    }

    // ------  private functions ------

    protected function delete_tasks_by_config_id($config) {
        
        $delete_tasks = array();
        
        $xml = $this->execute_command("<get_tasks />");
        
        if ($xml !== FALSE) {
            foreach ($xml->task as $task) { // save tasks with config_id = $config
                if($config == (string)$task->config->attributes()->id) {    $delete_tasks[]= (string)$task->attributes()->id;    }
            }
            foreach ($delete_tasks as $dtask) {
                if( $this->execute_command("<delete_task task_id=\"$dtask\" />") === FALSE) {
                    return FALSE;
                }
            }
            
            $this->execute_command("<empty_trashcan />");
            
            return TRUE;
        }
        else {
            return FALSE;
        }
    }


    private function get_allowed_users() {
    
        $users    = Session::get_users_to_assign($this->conn);
        
        $entities = (Session::is_pro()) ? Acl::get_entities_to_assign($this->conn) : array();
        
        $allowed_users_entities = array();
        
        foreach ($users as $user)
            $allowed_users_entities[] = $user->get_login();
            
        foreach ($entities as $entity_id => $data)
            $allowed_users_entities[] = $entity_id;
          
        return $allowed_users_entities;
    }


    // ------  public functions ------
    
    public function get_config_id_by_name_comment($name, $comment="") {

        $config_id = "";
    
        $xml = $this->execute_command ("<get_configs />");
        
        if ($xml === FALSE) { return $config_id; }

        foreach ($xml->config as $config) {
            if($comment!="") {
                if( ($name ==(string)$config->name) && ($comment==(string)$config->comment) ) {    $config_id = (string)$config->attributes()->id;    }
            }
            else {
                if( ($name ==(string)$config->name) ) {    $config_id = (string)$config->attributes()->id;    }
            }
        }
        return $config_id;
    }
    
    
    public function is_openvas8()
    {
        $result = FALSE;
        
        $xml = $this->execute_command("<help />");
        
        if($xml !== FALSE)
        {
            $xml_string = (string)$xml;
            
            if (!preg_match('/PAUSE_TASK/', $xml_string))
            {
                $result = TRUE;
            }
        }
        
        return $result;
    }


    public function set_plugins_by_family ($sid, $fam = "") {
    
        $this->conn->SetFetchMode(ADODB_FETCH_BOTH);
    
        $familyHash = array();
        $command = "";

        $id_config = $this->get_config_id_by_sid($sid);

        if ($id_config == "") { 
            $res["status"]  = "error";
            $res["message"] = _("Profile not found!");
            return $res;
        }

        if ($this->delete_tasks_by_config_id($id_config) === FALSE) {
            $res["status"]  = "error";
            $res["message"] = _("Couldn't delete the profile tasks!");
            return $res;
        }

        $this->execute_command("<empty_trashcan />");

        // Disable all families
        
        $fam_where = ( $fam != "" ) ? "WHERE id=$fam" : "";

        $result=$this->conn->Execute("SELECT name FROM vuln_nessus_family $fam_where");
        
        $command = "<commands>";
        while (!$result->EOF) {
            $fname = $result->fields['name'];
            $command .= "<modify_config config_id=\"$id_config\"><nvt_selection><family>$fname</family></nvt_selection></modify_config>";
            $result->MoveNext();
        }
        $command .= "</commands>";

        if ($this->execute_command($command) === FALSE) {
            $res["status"]  = "error";
            $res["message"] = $this->error_message;
            return $res;
        }
        
        // Select enabled plugins
        
        $fam_filter = ( $fam != "" ) ? "AND f.id=$fam" : "";

        $result=$this->conn->Execute("SELECT f.name as fname, p.oid as plugin_id FROM vuln_nessus_settings_plugins AS sp
                                            LEFT JOIN vuln_nessus_plugins AS p ON sp.id = p.id
                                            LEFT JOIN vuln_nessus_family AS f ON sp.family = f.id
                                            WHERE sp.enabled = 'Y'
                                            AND sp.sid = '$sid' $fam_filter");
        while (!$result->EOF) {
            $fname = $result->fields['fname'];
            $plugin_id = $result->fields['plugin_id'];
            $familyHash["$fname"]["$plugin_id"]++;
            $result->MoveNext();
        }

        // Update openvas-manager plugins
        
        foreach ($familyHash as $family => $v2) {
            $command = "<modify_config config_id=\"$id_config\"><nvt_selection><family>$family</family>";
            foreach ($v2 as $oid => $v3) {
                $command .= "<nvt oid=\"".$oid."\"/>";
            }
            $command .= "</nvt_selection></modify_config>";

            if ($this->execute_command($command) === FALSE) {
                $res["status"]  = "error";
                $res["message"] = $this->error_message;
                return $res;
            }
        }

        return ( array( "status" => "OK", "message" => "") );
    }


    public function set_preferences ($sid) {
        $this->conn->SetFetchMode(ADODB_FETCH_BOTH);
        
        $id_config = $this->get_config_id_by_sid($sid);
        $uuid      = Util::get_encryption_key();

        if ($id_config == "") { 
            $res["status"]  = "error";
            $res["message"] = _("Profile not found!");
            return $res;
        }


        if ($this->delete_tasks_by_config_id($id_config) === FALSE) {
            $res["status"]  = "error";
            $res["message"] = _("Couldn't delete the profile tasks!");
            return $res;
        }

        $this->execute_command("<empty_trashcan />");
        
        $command = "";
        
        
        // Select preferences
        
        $result=$this->conn->Execute("SELECT sp.nessus_id as nessus_id, sp.value as value, AES_DECRYPT(sp.value,'$uuid') as dvalue, sp.type, sp.category, p.oid as oid FROM vuln_nessus_settings_preferences AS sp
                                        LEFT JOIN vuln_nessus_plugins AS p ON p.id = sp.id
                                        WHERE sp.sid=$sid AND sp.value!=''");


        while (!$result->EOF) {
            if(!Util::is_utf8($result->fields['nessus_id'])) {
                $command .= "<modify_config config_id=\"$id_config\">";
                $command .= "<preference>";
                if($result->fields['oid']!="") {
                    $command .= "<nvt oid=\"".$result->fields['oid']."\"/>";
                }
                $command .= "<name>".$result->fields['nessus_id']."</name>";
                //$command .= "<name>".Util::utf8_encode2($result->fields['nessus_id'])."</name>";
                //$command .= "<name><![CDATA[".$result->fields['nessus_id']."]]></name>"; 
                $command .= "<value>".base64_encode((!empty($result->fields['dvalue'])) ? $result->fields['dvalue'] : $result->fields['value'])."</value>";
                
                //if($result->fields['type']=="P") {
                //    error_log("password: ".$result->fields['nessus_id']."-".base64_encode((!empty($result->fields['dvalue'])) ? $result->fields['dvalue'] : $result->fields['value'])."\n",3,"/tmp/setting.log");
                //}
                $command .= "</preference>";
                $command .= "</modify_config>\n";
                
                /*
                if ($result->fields['type']=="P") {
                    $result->fields['value'] = $this->conn->GetOne( "SELECT AES_DECRYPT('".$result->fields['value']."','".$uuid."')" );
                }
                
                $this->update_preferences_sqlite($id_config, $result->fields['category'], $result->fields['nessus_id'], $result->fields['value']);
                */
            }
            $result->MoveNext();
        }

        if ($command!="") {
            $command = "<commands>".$command."</commands>";

            if ($this->execute_command($command) === FALSE) {
				$res["status"]  = "error";
				$res["message"] = $this->error_message;
				return $res;
		    }
        }
        
        return ( array( "status" => "OK", "message" => "") );
    }

    public function are_there_pending_tasks() {
        $xml = $this->execute_command("<get_tasks />");
        
        foreach ($xml->task as $task) { 
            return true;
        }
        
        return false;
    }

    public function get_tasks_using_config($sid) {
        $running_tasks = array();
        
        $id_config = $this->get_config_id_by_sid($sid);
        
        if ($id_config =="") { return; }
        
        $xml = $this->execute_command("<get_tasks />");
        
        foreach ($xml->task as $task) { 
            if((string)$task->status != "Done" && $id_config == (string)$task->config->attributes()->id) {    $running_tasks[]= (string)$task->attributes()->id;    }
        }
        
        return $running_tasks;
    }


    /**
     * @codeCoverageIgnore
     */
    public function check_connection() {
        $xml = $this->execute_command("<help />");

        if($xml === FALSE) {
            return $this->error_message;
        }
        else {
            return "";
        }
    }


    /**
     * @codeCoverageIgnore
     */
    public function get_used_sids() {

        $this->conn->SetFetchMode(ADODB_FETCH_BOTH);

        $used_configs = array();
        $pname = "";
        $puser = "";
        $sids = array();

        $xml = $this->execute_command("<get_tasks />");

        if ($xml === FALSE) { return $sids; }

        foreach ($xml->task as $task) {
            if((string)$task->status != "Done" && (string)$task->status != "Stopped" && !in_array((string)$task->config->attributes()->id, $used_configs)) {
                $used_configs[]= (string)$task->config->attributes()->id;
            }
        }

        // get profile sid
        foreach($used_configs as $config) {
            $xml = $this->execute_command("<get_configs config_id=\"$config\"/>");
            foreach($xml->config as $config) {
                $pname = (string)$config->name;
                $puser = (string)$config->comment;
                $result=$this->conn->Execute("SELECT id FROM vuln_nessus_settings WHERE name='$pname' AND owner='$puser' LIMIT 1");
                $sids[] = $result->fields['id'];
            }
        }
        return $sids;
    }


    public function create_new_config($sid, $clone_id) {

        $default_profiles = array('1' => 'Deep', '2' => 'Default', '3' => 'Ultimate');

        $this->conn->SetFetchMode(ADODB_FETCH_BOTH);

        $result=$this->conn->Execute("SELECT name, owner FROM vuln_nessus_settings WHERE id='$sid' LIMIT 1");

        $pname = $result->fields['name'];
        $puser = $result->fields['owner'];

        $id_config = $this->get_config_id_by_sid($sid);

        if (array_key_exists($clone_id, $default_profiles))
        {
            $id_to_clone = $this->get_config_id_by_name_comment($default_profiles[$clone_id]);
            $result      = $this->execute_command("<create_config><copy>$id_to_clone</copy><name>$pname</name><comment>$puser</comment></create_config>");

            if ($result === FALSE)
            {
                return ( array("message" => $this->error_message, "status" => "error") );
            }
        }
        else if($id_config != '')
        {
            $result = $this->set_plugins_by_family($sid);

            if($result["status"] == "error") {
                return $result;
            }

            $result = $this->set_preferences($sid);

            if($result["status"] == "error") {
                return $result;
            }
        }
        else
        {
            $id_ff = $this->get_config_id_by_name_comment("Full and fast");
            $this->execute_command("<create_config><copy>".$id_ff."</copy><name>$pname</name><comment>$puser</comment></create_config>");
            $result = $this->set_plugins_by_family($sid);

            if($result["status"] == "error") {
                return $result;
            }

            $result = $this->set_preferences($sid);

            if($result["status"] == "error") {
                return $result;
            }
        }

        return ( array("message" => "", "status" => "OK") );
    }


    /**
     * @codeCoverageIgnoreStart
     */
    public function play_task($job_id){

        $this->conn->SetFetchMode(ADODB_FETCH_BOTH);

        $result = $this->conn->Execute("SELECT meth_CPLUGINS FROM vuln_jobs WHERE id=$job_id");
        $config_id = $result->fields["meth_CPLUGINS"];

        $this->execute_command ("<start_task task_id=\"$config_id\" />");

    }


    public function pause_task($job_id){

        $this->conn->SetFetchMode(ADODB_FETCH_BOTH);

        $result = $this->conn->Execute("SELECT meth_CPLUGINS FROM vuln_jobs WHERE id=$job_id");
        $config_id = $result->fields["meth_CPLUGINS"];

        $this->execute_command ("<pause_task task_id=\"$config_id\" />");

    }


    public function stop_task($job_id){

        $this->conn->SetFetchMode(ADODB_FETCH_BOTH);

        $result = $this->conn->Execute("SELECT meth_CPLUGINS FROM vuln_jobs WHERE id=$job_id");
        $config_id = $result->fields["meth_CPLUGINS"];

        $this->execute_command ("<stop_task task_id=\"$config_id\" />");

    }


    public function delete_task($job_id){

        $this->conn->SetFetchMode(ADODB_FETCH_BOTH);

        $result = $this->conn->Execute("SELECT meth_CPLUGINS FROM vuln_jobs WHERE id=$job_id");
        $config_id = $result->fields["meth_CPLUGINS"];

        $tstatus = $this->get_task_status($job_id);

        if($tstatus["status"]!="") {
            if($tstatus["status"]!="Stopped") {
                $this->stop_task($job_id);
            }
            $this->execute_command ("<delete_task task_id=\"$config_id\" />");
        }
    }


    public function resume_task($job_id) {
    
        $this->conn->SetFetchMode(ADODB_FETCH_BOTH);
                
        $result = $this->conn->Execute("SELECT meth_CPLUGINS FROM vuln_jobs WHERE id=$job_id");
        $config_id = $result->fields["meth_CPLUGINS"];
        
        $task_status = $this->get_task_status($job_id);
        
        if( preg_match("/^stopped.*/i", $task_status["status"]) ) {
            $this->execute_command ("<resume_stopped_task task_id=\"$config_id\" />");
        }
        else {
            $this->execute_command ("<resume_paused_task task_id=\"$config_id\" />");
        }
    }
    /*
     * @codeCoverageIgnoreEnd
     */

    public function get_task_status($job_id) {
        
        $this->conn->SetFetchMode(ADODB_FETCH_BOTH);
        
        $status = array("status"=>"", "progress"=>"");
        
        $result = $this->conn->Execute("SELECT meth_CPLUGINS FROM vuln_jobs WHERE id=$job_id");
        $config_id = $result->fields["meth_CPLUGINS"];
        
        $xml = $this->execute_command("<get_tasks task_id=\"$config_id\"/>");
        
        if ($xml === FALSE) { return ($status); }
        
        $status["status"] = trim((string) $xml->task[0]->status);
        $status["progress"] = trim((string) $xml->task[0]->progress);
        
        return ($status);

    }


    public function get_task_detail_by_id($states, $job_id = '', $plain_text = FALSE) 
    {
		if($job_id == '')
		{
			//return ( array('total' => '', 'detail' => '') ) ;
			return "NO_DATA_AVAILABLE";
		}
		
		$this->conn->SetFetchMode(ADODB_FETCH_BOTH);
        
        $tasks_info_arr = array();
        
        $arr_states = explode("|", $states);        
                
        $result_servers=$this->conn->Execute("SELECT DISTINCT meth_Wcheck, meth_CPLUGINS FROM vuln_jobs WHERE id=$job_id");
        
        $server_ip = $result_servers->fields['meth_Wcheck'];
		$task_id   = $result_servers->fields['meth_CPLUGINS'];

        preg_match("/.*\s(\d+\.\d+\.\d+\.\d+)<.*/",$server_ip,$found);

        if ($found[1] != '')
        {
            $sensor_id     = Av_sensor::get_id_by_ip($this->conn, $found[1]);

            $sensor_object = new Av_sensor($sensor_id);
        
            $sensor_object->load_from_db($this->conn);
                
            $ov_credentials = $sensor_object->get_vs_credentials($this->conn);
                        
            $port     = $ov_credentials['port'];
            
            $user     = $ov_credentials['user'];
            
            $password = $ov_credentials['password'];
                
            $this->set_server_properties($found[1], $port, $user, $password);
        }
		else 
		{
			//return ( array("total" => "", "detail" => "") ) ;
			return "NO_DATA_AVAILABLE";
		}
            
		$xml = $this->execute_command("<get_tasks />");
		//There's no XML
		if ($xml === FALSE) {
			return "NO_DATA_AVAILABLE";
		};
            
        $allowed_users = $this->get_allowed_users();

	$task_prg_image = function($prg) {
		$prg_states = array("green","green","green","green");
		switch (true) {
			case $prg <= 25: $prg_states = array("yellow","gray","gray","gray"); break;
			case $prg <= 50: $prg_states = array("green","yellow","gray","gray"); break;
			case $prg <= 75: $prg_states = array("green","green","yellow","gray"); break;
			case $prg <= 99: $prg_states = array("green","green","green","yellow"); break;
		}
		$task_progress="";
		for ($i=0;$i<3;$i++) {
			$task_progress .= "<img src='./images/light_{$prg_states[$i]}_lit.png' border='0'/>";
		}
		$task_progress .= "<img style='padding-right:7px;' src='./images/light_{$prg_states[$i]}_lit.png' border='0'/>";
		return $task_progress;
	};


        foreach ($xml->task as $task)
        {

			if( $task_id == (string)$task->attributes()->id ) 
			{
				$task_id = $task->attributes()->id;
				$result = $this->conn->Execute("SELECT id, username FROM vuln_jobs WHERE meth_CPLUGINS='$task_id'");
				$username = $result->fields["username"];
				if( (in_array($username, $allowed_users) || Session::am_i_admin()) && in_array((string)$task->status, $arr_states) ) {
					$task_progress = $task_prg_image((int)$task->progress);

					$tstatus = $this->get_task_status($result->fields["id"]);
					$simage = "";

					if ($tstatus["status"]=="Paused") { $simage = "<img align='absmiddle' style='padding:2px 4px 2px 0px' src='./images/paused.png' border='0'/>"; }
					else if ($tstatus["status"]=="Running") { $simage = "<img align='absmiddle' style='padding:2px 4px 2px 0px' src='./images/running.png' border='0'/>"; }
					else if ($tstatus["status"]=="Requested" || $tstatus["status"]=="Pause Requested") { $simage = "<img align='absmiddle' style='padding:2px 4px 2px 0px' src='./images/requested.png' border='0'/>"; }
					   
					//Special case, the task is starting but there's no host_progress yet
					if(count($task->progress->host_progress) == 0 && ($tstatus["status"]=="Running" || $tstatus["status"]=="Requested")) {
						return " |0";
					}

					$i = 1;
					foreach($task->progress->host_progress as $hprogress) 
					{
						$tasks_info = "";
						if(!$plain_text) 
						{
							$host_progress = $task_prg_image((int)$hprogress);
							$tasks_info .= "<strong>".(string)$hprogress->host."</strong>|";
						}
						else 
						{
							$tasks_info .= md5((string)$hprogress->host).";";
							$host_progress = (int)$hprogress;
						}
						if(!$plain_text) 
						{
							$tasks_info .= "<div style='float:left;width:55%;text-align:right;padding:3px 0px 0px 0px'>".$host_progress."</div><div style='float:right;width:43%;text-align:left'>".trim((string)$hprogress)."%</div>";
						}
						else 
						{
							$tasks_info .= $host_progress;
						}

						$tasks_info_arr [] = $tasks_info;
						$i++;
					}
				}
			}
        }
        return  implode("#", $tasks_info_arr);
    }


    public function delete_config($sid) 
    {
        $config_id = $this->get_config_id_by_sid($sid);
        
        if($this->delete_tasks_by_config_id($config_id) === FALSE) 
        {
            $res["status"]  = "error";
            $res["message"] = _("Couldn't delete the profile tasks!");
            return $res;
        }
        
        if($this->execute_command ("<delete_config config_id=\"$config_id\" />") === FALSE) 
        {
            $res["status"]  = "error";
            $res["message"] = $this->error_message;
            return $res;
        }
        
        return (array("status" => "OK", "message" => ""));
    }


    public function set_server_properties($ip, $port, $user, $password) 
    {
        $this->ip       = $ip;
        $this->port     = $port;
        $this->user     = $user;
        $this->password = $password;

        $this->user     = str_replace("'","'\"'\"'",$this->user);
        $this->password = str_replace("'","'\"'\"'",$this->password);
    }

    public function get_ip(){
        return $this->ip;
    }

    public function get_port(){
        return $this->port;
    }

    public function get_user(){
        return $this->user;
    }

    public function get_password(){
        return $this->password;
    }

    public function get_binary_location(){
        return $this->binary_location;
    }


    public function update_preferences_sqlite($uuid, $category, $pref_name, $pref_value) 
    {
        $sqlite = new Omp_sqlite("/var/lib/openvas/mgr/tasks.db");

        $sqlite->connect_db();

        // get "config id" from configs table

        $result    = $sqlite->execute_db("SELECT id FROM configs WHERE uuid='".$uuid."'");
        $row       = $sqlite->fetch_row_db($result);
        $config_id = $row["id"];
        


        // get preference id (id field)from config to modify the preference

        $result = $sqlite->execute_db("SELECT id FROM config_preferences WHERE config ='".$config_id."' AND name='".$pref_name."'");
        $row = $sqlite->fetch_row_db($result);
        $preference_id = $row["id"];

        // update if preference exists
        if($preference_id != "") 
        {
            $result = $sqlite->execute_db("UPDATE config_preferences SET value = '".$pref_value."' where config = '".$config_id."' AND name = '".$pref_name."'");
        }
        else 
        { // else insert
            $result = $sqlite->execute_db("SELECT MAX(id)+1 as next_id FROM config_preferences");
            $row = $sqlite->fetch_row_db($result);
            $next_id = $row["next_id"];
            
            $sqlite->execute_db("INSERT INTO config_preferences (id, config, type, name, value) VALUES ('".$next_id."', '".$config_id."', '".$category."', '".$pref_name."', '".$pref_value."')");
        }
    }
}

/* End of file omp.inc */
/* Location: ../include/classes/omp.inc */

<?php
namespace Neko\Auth;
use Neko\Database\DB;
use Neko\Facade\Session;
use Neko\Validation\Validator;
use Neko\Framework\Util\Date;
use Neko\Framework\Util\Account;

trait Authentication
{

    public function adminLoginForm()
    {
        if(Account::getid()!==false)
        {
            db::table('tb_user')->where('id', Account::getid())->update(array(
                'islogin' => '0'
            ));
        }
        return view('theme_admin.view.login');
    }

    public function userLoginForm()
    {
        return view('theme_user.view.login');
    }

    public function userShowLogout()
    {        
        $self = $this;
        app()->on('logout_ok', function($data) use ($self){
            $self->logout_ok();
        });

        app()->hook->apply('logout_ok_before', [$this->request]);
        app()->hook->apply('logout_ok', [$this->request]);
        app()->hook->apply('logout_ok_after', [$this->request]);
        return view('theme_user.view.logout');
    }

    public function dologout()
    {
        $self = $this;
        app()->on('logout_ok', function($data) use ($self){
            $self->logout_ok();
        });

        app()->hook->apply('logout_ok_before', [$this->request]);
        app()->hook->apply('logout_ok', [$this->request]);
        app()->hook->apply('logout_ok_after', [$this->request]);
    }
    
    public function dologin()
    {
        app()->hook->apply('onDoLogin', [$this->request]);


        app()->hook->apply('login_before', [$this->request]);

        $validator = new Validator;
        $validation = $validator->make($_POST, [
            'username'              => 'required',
            'password'              => 'required|min:6',
        ]);
        
        $validation->validate();

        if ($validation->fails()){
            $errors = $validation->errors();
            return response()->json($errors->validateError(), 401);
        } else {
            $username = $this->request->get('username');
            $password = $this->request->get('password');
            $login_data = db::table('tb_user')
            ->where('tb_user.username','=', $username)
            ->where('tb_user.password','=', md5($password))
            ->orwhere('tb_user.email','=', $username)
            ->where('tb_user.password','=', md5($password));
            if($login_data->exists())
            {
                $access = db::table('tb_user_permissions')
                ->join('tb_user_roles', 'tb_user_roles.id_group', '=', 'tb_user_permissions.id_group')
                ->select('tb_user_permissions.id_group','tb_user_permissions.route',db::raw('sum(acc) as acc'),db::raw('sum(wrt) as "add"'),db::raw('sum(edt) as edt'),db::raw('sum(del) as del'),db::raw('sum(exec) as exec'))//
                ->where('tb_user_roles.user_id','=',$login_data->first()['id'])
                ->groupBy('tb_user_permissions.route','tb_user_permissions.id_group')
                ->get();

                $role = db::table('tb_user_roles')
                ->join('tb_user_group', 'tb_user_roles.id_group', '=', 'tb_user_group.id')
                ->select('tb_user_group.nm_group')
                ->where('tb_user_roles.user_id','=',$login_data->first()['id'])->lists("nm_group");
                
                $self = $this;
                app()->on('login_ok', function($status) use ($login_data,$role,$access,$self){
                    //$token = $self->login_token($login_data);
                    $token = "";
                    $self->login_ok($login_data,$role,$access,$token);
                });

                app()->hook->apply('login_ok_before', [$login_data,$role,$access]);
                app()->hook->apply('login_ok', [$login_data]);
                app()->hook->apply('login_ok_after', [$login_data,$role,$access]);
                
            }else{
                return response()->json(
                    array(
                        "title"=>"Login Failed",
                        "message"=>"Username or Password is invalid!",
                        "error"=>array()
                    ), 401);
            }

        }

    }
    
    public function login_token($login_data)
    {
        $jwt = new JWT($_ENV['JWT_SECRET'], 'HS256', 1, 10);
        $jwt_refresh = new JWT($_ENV['JWT_SECRET'], 'HS256', 3600, 0);
        
        $token = $jwt->encode([
            'uid'    => $login_data->first()['id'],
            'aud'    => config('app.base_url'),
            'scopes' => ['user'],
            'iss'    => app()->config['app.api_url'],
        ]);

        $refresh = $jwt_refresh->encode([
            'uid'    => $login_data->first()['id'],
            'aud'    => config('app.base_url'),
            'scopes' => ['user'],
            'iss'    => app()->config['app.api_url'],
        ]);

        return array("access"=>$token,"refresh"=>$refresh);
    }

    public function login_ok($login_data,$role,$access,$token)
    {
        Session::set("user",array("account"=>$login_data->first(),"role"=>$role,"access"=>$access));
        db::table('tb_user')->where('id', $login_data->first()['id'])->update(array(
            'date_lastlogin' => Date::now(),
            'islogin' => '1'
        ));
        
        return response()->json(
            array(
                "title"=>"Login Success",
                "message"=>"You've logged succesfully!",
                // "token" => $token['access'],
                // "refresh" => explode(".",$token['refresh'][2]),
            ), 200);
    }

    public function logout_ok()
    {
        db::table('tb_user')->where('id', Account::getid())->update(array(
            'islogin' => '0'
        ));
        Session::flush();
        return response()->json(
            array(
                "title"=>"Logout Success",
                "message"=>"You've logout succesfully!",
            ), 200
        );
    }
    
}


?>
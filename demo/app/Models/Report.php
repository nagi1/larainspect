<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class Report extends Model
{
    public function insecureSummary(Request $request): array
    {
        $column = $request->query('column', 'name desc');
        $filter = $request->query('filter', '1 = 1');
        $email = $request->query('email', 'admin@example.com');

        return [
            'select' => DB::table('users')->select(DB::raw($column))->whereRaw($filter)->limit(5)->get(),
            'raw' => DB::select("select * from users where email = '".$email."'"),
        ];
    }
}

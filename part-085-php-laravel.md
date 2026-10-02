# Part 085: SQL Injection ใน PHP Laravel

## ภาพรวม

Laravel, Eloquent ORM และ raw queries - บั่งเสี่ยงและป้องกัน

**ขั้นตอนที่ 1346-1360**

---

## 1346. Laravel Query Builder

```php
use Illuminate\Support\Facades\DB;

// VULNERABLE: ใช้ raw แบบ concat
public function searchVulnerable(string $name)
{
    return DB::select("SELECT * FROM products WHERE name = '$name'");
    // SQL injection!
}

// SECURE: bindings ใน DB::select()
public function searchSafe(string $name)
{
    return DB::select('SELECT * FROM products WHERE name = ?', [$name]);
}

// SECURE: Query Builder (ดีที่สุด)
public function searchBuilder(string $name)
{
    return DB::table('products')
        ->where('name', $name)
        ->get();
}

// VULNERABLE: orderByRaw แบบ concat
public function listProductsVuln(string $column)
{
    return DB::table('products')->orderByRaw($column)->get();
}

// SECURE: whitelist
public function listProductsSafe(string $column)
{
    $allowed = ['name', 'price', 'created_at'];
    if (!in_array($column, $allowed)) {
        abort(400, 'Invalid column');
    }
    return DB::table('products')->orderBy($column)->get();
}
```

---

## 1347. Eloquent ORM

```php
use App\Models\User;
use Illuminate\Database\Eloquent\Builder;

// SAFE: Eloquent สามารถใช้ได้โดยตรง
$user = User::find($id);  // safe - int key
$users = User::where('email', $email)->first();  // safe
$users = User::where('name', 'like', "%$search%")->get();  // safe

// VULNERABLE: whereRaw แบบ concat
$users = User::whereRaw("email = '$email'")->get();  // DANGER!

// SECURE: whereRaw แบบ bindings
$users = User::whereRaw('email = ?', [$email])->get();  // safe

// VULNERABLE: ใช้ user input ใน select
$field = $_GET['field'];  // could be malicious
$orders = Order::select($field)->get();  // DANGER!

// SECURE: whitelist
$allowed = ['id', 'product_name', 'amount'];
$field = in_array($field, $allowed) ? $field : 'id';
$orders = Order::select($field)->get();
```

---

## 1348. Laravel Input Validation

```php
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;

class ProductController extends Controller
{
    public function search(Request $request)
    {
        // Validate ก่อนใช้
        $validated = $request->validate([
            'category_id' => 'required|integer|min:1',
            'name'        => 'sometimes|string|max:100|regex:/^[a-zA-Z0-9 ]+$/',
            'sort'        => ['sometimes', Rule::in(['name', 'price', 'created_at'])],
        ]);
        
        $query = Product::where('category_id', $validated['category_id']);
        
        if (isset($validated['name'])) {
            $query->where('name', 'like', '%' . $validated['name'] . '%');
        }
        
        if (isset($validated['sort'])) {
            $query->orderBy($validated['sort']);
        }
        
        return response()->json($query->get());
    }
}
```

---

## 1349. Laravel raw SQL เมื่อจำเป็น

```php
// เมื่อต้องใช้ raw SQL (เช่น complex joins):

// SECURE: named bindings
$results = DB::select(
    'SELECT u.name, COUNT(o.id) as order_count 
     FROM users u 
     LEFT JOIN orders o ON u.id = o.user_id 
     WHERE u.created_at > :date 
     GROUP BY u.id, u.name 
     HAVING order_count > :min_orders',
    [
        'date'       => $date->toDateString(),
        'min_orders' => 5,
    ]
);

// DB::statement สำหรับ DDL:
DB::statement('CREATE INDEX IF NOT EXISTS idx_email ON users (email)');

// หลีกเลี่ยง SQL debug logging:
if (config('app.debug')) {
    DB::enableQueryLog();
    // ... run queries ...
    \Log::debug('Queries:', DB::getQueryLog());
}
```

---

## สรุป

PHP Laravel SQLi:
- **Query Builder** - `where('col', $val)` = safe
- **Eloquent** - `whereRaw('? ...', [$val])` bindings
- **Validation** - Rule::in() whitelist
- **Raw SQL** - named `:param` bindings

---

*Part 085 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

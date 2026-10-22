<?php

namespace App\Http\Controllers\ApiV1;

use App\Http\Controllers\Controller;
use App\Http\Controllers\DocumentFormController;
use App\Models\Contact;
use App\Models\DocumentType;
use App\Models\Product;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpKernel\Exception\HttpException;

/** Utilidades comunes de la API /api/v1: paginación, permisos del usuario dueño de la llave y referencias por id o por código. */
abstract class ApiBaseController extends Controller
{
    protected function perPage(Request $request): int
    {
        return min(100, max(1, $request->integer('por_pagina', 50)));
    }

    protected function paged(LengthAwarePaginator $page, callable $map): JsonResponse
    {
        return response()->json([
            'data' => collect($page->items())->map($map)->values(),
            'pagina' => $page->currentPage(), 'por_pagina' => $page->perPage(), 'total' => $page->total(), 'paginas' => $page->lastPage(),
        ]);
    }

    /** La llave actúa con los permisos del usuario que la creó. */
    protected function authorizeApi(string $permission): void
    {
        $user = Auth::user();
        if (! $user || ! Gate::forUser($user)->allows($permission)) {
            throw new HttpException(403, "El usuario de la llave no tiene el permiso {$permission}.");
        }
    }

    /** Tercero por "<campo>_id" o por {"identificacion", "sucursal"} dentro de "<campo>". */
    protected function contactFrom(array $data, string $field): Contact
    {
        if (! empty($data[$field.'_id'])) {
            return Contact::query()->find((int) $data[$field.'_id'])
                ?? throw ValidationException::withMessages([$field.'_id' => "No existe el {$field} con id {$data[$field.'_id']}."]);
        }
        $ref = $data[$field] ?? null;
        $id = is_array($ref) ? ($ref['identificacion'] ?? null) : $ref;
        if (! $id) {
            throw ValidationException::withMessages([$field => "Indica el {$field} con \"{$field}_id\" o con \"{$field}\": {\"identificacion\": \"...\"}."]);
        }
        $id = preg_replace('/\D/', '', (string) $id) ?: (string) $id;

        return Contact::query()->where('identification', $id)->where('branch_office', (int) (is_array($ref) ? ($ref['sucursal'] ?? 0) : 0))->first()
            ?? throw ValidationException::withMessages([$field => "No existe un tercero con identificación {$id}. Créalo primero con POST /terceros."]);
    }

    /** Producto por "producto_id" o por "codigo". */
    protected function productFrom(array $item, int $n): ?Product
    {
        if (! empty($item['producto_id'])) {
            return Product::query()->find((int) $item['producto_id']) ?? throw ValidationException::withMessages(["items.$n.producto_id" => "No existe el producto con id {$item['producto_id']}."]);
        }
        if (! empty($item['codigo'])) {
            return Product::query()->where('code', $item['codigo'])->first() ?? throw ValidationException::withMessages(["items.$n.codigo" => "No existe el producto con código {$item['codigo']}."]);
        }

        return null;
    }

    /**
     * Tipo de documento indicado o, si no se indica, el primero activo (prefiriendo el electrónico en facturas y notas).
     * Sin tipos configurados devuelve el tipo base ("CE-1") que la numeración crea al guardar, como en la pantalla.
     */
    protected function documentType(array $data, string $type): int|string|null
    {
        if (! empty($data['tipo_documento_id'])) {
            $doc = DocumentType::query()->where('type', $type)->find((int) $data['tipo_documento_id'])
                ?? throw ValidationException::withMessages(['tipo_documento_id' => "El tipo de documento {$data['tipo_documento_id']} no existe o no es de tipo {$type}. Consulta GET /tipos-documento?tipo={$type}."]);

            return $doc->id;
        }
        $types = DocumentType::query()->where('type', $type)->where('active', true)->orderBy('code')->get();

        $fallback = DocumentFormController::FALLBACK_TYPES[$type][0]['code'] ?? null;

        return ($types->first(fn ($t) => $t->isElectronic()) ?? $types->first())?->id ?? ($fallback !== null ? "{$type}-{$fallback}" : null);
    }

    /** Ejecuta una operación de negocio y convierte sus errores en respuestas 422. */
    protected function attempt(callable $fn): mixed
    {
        try {
            return $fn();
        } catch (\RuntimeException $e) {
            if ($e instanceof HttpException || $e instanceof ValidationException) {
                throw $e;
            }
            throw ValidationException::withMessages(['documento' => $e->getMessage()]);
        }
    }
}

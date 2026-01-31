using Dummiesman;
using System.Runtime.InteropServices;
using UnityEngine;

#nullable enable
namespace Host
{
    class Mesh : StaticResource
    {
        public UnityEngine.Mesh? UnityMesh;
        public Mesh(string file_name) : base(file_name) {
        }
        public override void Init()
        {
            UnityMesh = new();
        }
        public override void UpdateMMFRead()
        {
            if (CurrentSize != Size)
                throw new System.Exception("mesh file not loaded at once");

            var stream = _mmf.CreateViewStream(Marshal.SizeOf<StaticResourceHeader>(), Size);
            var result_gameobject = new OBJLoader().Load(stream);
            var mesh = result_gameobject.transform.GetChild(0).GetComponent<MeshFilter>().sharedMesh;
            FlipMeshX(mesh);
            OverwriteMesh(mesh, UnityMesh!);
            UnityEngine.Object.Destroy(result_gameobject);
        }
        private static void OverwriteMesh(UnityEngine.Mesh src, UnityEngine.Mesh dst)
        {
            dst.Clear(keepVertexLayout: false);
            dst.indexFormat = src.indexFormat;
            dst.subMeshCount = src.subMeshCount;

            dst.SetVertices(src.vertices);
            if (src.normals != null && src.normals.Length == src.vertexCount)
                dst.SetNormals(src.normals);
            if (src.tangents != null && src.tangents.Length == src.vertexCount)
                dst.SetTangents(src.tangents);

            //// 1. Flip vertices
            //Vector3[] vertices = src.vertices;
            //for (int i = 0; i < vertices.Length; i++)
            //    vertices[i].x = -vertices[i].x;
            //dst.SetVertices(vertices);

            //// 2. Flip normals
            //Vector3[]? normals = src.normals;
            //if (normals != null)
            //{
            //    for (int i = 0; i < normals.Length; i++)
            //        normals[i].x = -normals[i].x;
            //    dst.SetNormals(normals);
            //}

            //// 3. Flip tangents (tangents are Vector4)
            //Vector4[] tangents = src.tangents;
            //if (tangents != null)
            //{
            //    for (int i = 0; i < tangents.Length; i++)
            //        tangents[i].x = -tangents[i].x;
            //    dst.SetTangents(tangents);
            //}

            if (src.colors != null && src.colors.Length == src.vertexCount) dst.SetColors(src.colors);
            if (src.uv != null && src.uv.Length == src.vertexCount) dst.SetUVs(0, src.uv);
            if (src.uv2 != null && src.uv2.Length == src.vertexCount) dst.SetUVs(1, src.uv2);
            if (src.uv3 != null && src.uv3.Length == src.vertexCount) dst.SetUVs(2, src.uv3);
            if (src.uv4 != null && src.uv4.Length == src.vertexCount) dst.SetUVs(3, src.uv4);

            // Indices per submesh
            for (int i = 0; i < src.subMeshCount; i++)
            {
                var desc = src.GetSubMesh(i);
                var indices = src.GetIndices(i, applyBaseVertex: false);
                dst.SetIndices(indices, desc.topology, i, calculateBounds: false);
            }

            // Skinning (if present)
            if (src.bindposes != null && src.bindposes.Length > 0) dst.bindposes = src.bindposes;
            if (src.boneWeights != null && src.boneWeights.Length == src.vertexCount) dst.boneWeights = src.boneWeights;

            // Bounds
            dst.bounds = src.bounds;
        }
        private static void FlipMeshX(UnityEngine.Mesh mesh)
        {
            // Flip vertex positions
            Vector3[] vertices = mesh.vertices;
            for (int i = 0; i < vertices.Length; i++)
                vertices[i].x *= -1f;
            mesh.vertices = vertices;

            // Flip normals
            Vector3[] normals = mesh.normals;
            for (int i = 0; i < normals.Length; i++)
                normals[i].x *= -1f;
            mesh.normals = normals;

            // Flip tangents
            Vector4[] tangents = mesh.tangents;
            for (int i = 0; i < tangents.Length; i++)
                tangents[i].x *= -1f;
            mesh.tangents = tangents;

            // Reverse triangle winding order to fix backface culling
            int[] triangles = mesh.triangles;
            for (int i = 0; i < triangles.Length; i += 3)
            {
                // swap indices 0 and 2 of each triangle
                int tmp = triangles[i];
                triangles[i] = triangles[i + 2];
                triangles[i + 2] = tmp;
            }
            mesh.triangles = triangles;

            // Recalculate bounds
            mesh.RecalculateBounds();
        }
        public override void Dispose()
        {
            base.Dispose();
        }
    }
}
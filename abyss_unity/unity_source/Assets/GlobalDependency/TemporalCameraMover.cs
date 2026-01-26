using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.InputSystem;

public class TemporalCameraMover : MonoBehaviour
{
    public float rotationSpeed;
    public float moveSpeed;

    private float pitch = 0.0f;  // Up/Down rotation (X-axis)
    private float yaw = 0.0f;    // Left/Right rotation (Y-axis)
    public void Rotate(Vector2 amount)
    {
        // Get the input and multiply by the rotation speed
        yaw += amount.x * rotationSpeed;
        pitch -= amount.y * rotationSpeed;

        // Clamp pitch to avoid looking too far up or down
        pitch = Mathf.Clamp(pitch, -90f, 90f);

        // Apply the rotation
        transform.localEulerAngles = new Vector3(pitch, yaw, 0f);
    }
    public void Move(Vector3 amount)
    {
        Vector3 forwardMovement = transform.forward * amount.z;
        Vector3 rightMovement = transform.right * amount.x;
        Vector3 upMovement = transform.up * amount.y;

        Vector3 movement = (forwardMovement + rightMovement + upMovement) * moveSpeed;
        transform.position += movement;
    }
    public void Reset()
    {
        transform.SetPositionAndRotation(Vector3.zero, Quaternion.identity);
    }
}

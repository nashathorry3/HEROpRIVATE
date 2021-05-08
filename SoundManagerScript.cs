/*using System.Collections;
using System.Collections.Generic;
using UnityEngine;

public class SoundManagerScript : MonoBehaviour
{
    // Start is called before the first frame

    public static AudioClip Fire;
    static AudioSource audioSrc;
    void Start()
    {
        Fire = Resources.load<AudioCLips>("fire");
        audioSrc = GetComponent<AudioSource>();
    }

    // Update is called once per frame
    void Update()
    {
        
    }
    public static void Playsound(string clip)
    {
        switch (clip)
        {
            case "fire":
                audioSrc.playOneShot(fire);
        }
    }
}*/

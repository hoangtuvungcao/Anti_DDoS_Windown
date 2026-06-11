package main

import (
	"image"
	"image/png"
	"os"
)

func main() {
	in, err := os.Open("icon.png")
	if err != nil {
		panic(err)
	}
	defer in.Close()

	src, err := png.Decode(in)
	if err != nil {
		panic(err)
	}

	dst := image.NewRGBA(image.Rect(0, 0, 256, 256))
	
	for y := 0; y < 256; y++ {
		for x := 0; x < 256; x++ {
			srcX := x * src.Bounds().Dx() / 256
			srcY := y * src.Bounds().Dy() / 256
			dst.Set(x, y, src.At(srcX, srcY))
		}
	}

	out, err := os.Create("icon_resized.png")
	if err != nil {
		panic(err)
	}
	defer out.Close()

	png.Encode(out, dst)
}

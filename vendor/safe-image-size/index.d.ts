export interface ImageDimensions {
  width: number;
  height: number;
  type: "png" | "gif" | "jpg" | "webp" | "svg";
}

export declare function imageSize(input: ArrayBuffer | ArrayBufferView): ImageDimensions;
export default imageSize;

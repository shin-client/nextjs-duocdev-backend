import { randomId } from '@/utils/helpers'
import { MultipartFile } from '@fastify/multipart'
import path from 'path'
import fs from 'fs'
import util from 'util'
import { pipeline } from 'stream'
import envConfig, { API_URL } from '@/config'
const pump = util.promisify(pipeline)

// Có thể thêm check file type sau khi upload xong
// import fileType from 'file-type' // Cài libary file-type
// const type = await fileType.fromFile(filepath)
// if (!type || !type.mime.startsWith('image/')) {
//   await fs.unlinkSync(filepath)
//   throw new Error('File upload không phải là ảnh hợp lệ')
// }

export const uploadImage = async (data: MultipartFile) => {
  const uniqueId = randomId()
  const ext = path.extname(data.filename)
  // Validate ext
  const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp']
  if (!allowedMimeTypes.includes(data.mimetype)) {
    throw new Error('Chỉ cho phép upload file ảnh (jpg, jpeg, png, gif, webp)')
  }
  const id = uniqueId + ext
  const filepath = path.resolve(envConfig.UPLOAD_FOLDER, id)
  await pump(data.file, fs.createWriteStream(filepath))
  if (data.file.truncated) {
    // Xóa file nếu file bị trucated
    fs.unlinkSync(filepath)
    throw new Error('Giới hạn file là 10MB')
  }
  const url = `${API_URL}` + '/static/' + id
  return url
}

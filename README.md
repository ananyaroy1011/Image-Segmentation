# SegNet : Deep Convolutional Encoder-Decoder Architecture for Pixel-wise Image Segmentation

This Project is implemented based on the following research paper:
<a href="https://github.com/chandnii7/SegNet/blob/main/Doc/Project_Research_Paper.pdf">View Research Paper</a>
<br />
Program was implemented using Python, TenserFlow, Keras and OpenCV. Refer the report for further implementation details:
<a href="https://github.com/chandnii7/SegNet/blob/main/Doc/Project_Report.pdf">View Report</a>
<br/>
CamVid dataset is used for training. Download CamVid dataset from provided drive link into CamVid folder:
<a href="https://drive.google.com/drive/folders/1rE23coR6ddOWOPtg4oB6qeIVzmYzvGt4?usp=sharing">Download CamVid</a>
<br/>
Trained Model weights can be downloaded from provided drive link into Model folder:
<a href="https://drive.google.com/drive/folders/1_CjpC_oRFYLw-KfV-p5xjKQarDiAeTk1?usp=sharing">Download Model</a>
<br/><br/>
<img src="https://github.com/chandnii7/SegNet/blob/main/Data/img1.jpg" height="300" width="800"/>
<br/><br/>

### Network Architecture<br/>
Overview:
* Contains encoder network and corresponding decoder network which will consist of a hierarchy of decoders one corresponding to each encoder
* Encoder network has 13 convolutional layers
* Decoder network has 13 layers corresponding to each encoder
* Non-linear upsampling in decoder using pooling indices from max-pooling step of the corresponding encoder for accurate boundary localization
* Upsampling maps are convolved with trainable filters to produce dense feature maps in decoder because upsampling maps are spared
* Followed by final pixel-wise classification layer using Softmax
* Dataset augmentation with albumentations
<br/>
<img src="https://github.com/chandnii7/SegNet/blob/main/Data/img2.jpg" height="300" width="450"/>
<br/>

### Results:
1. Comparing Ground Truth and Predictions of Trained Model:
<img src="https://github.com/chandnii7/SegNet/blob/main/Data/img3.jpg" height="300" width="700"/>
<br />

2. Evaluation of SegNet on Train, Validation, and Test Data:
<img src="https://github.com/chandnii7/SegNet/blob/main/Data/img4.jpg" height="300" width="450"/>
<br />

3. Precision, Recall, F1-score and Support:
<img src="https://github.com/chandnii7/SegNet/blob/main/Data/img5.jpg" height="700" width="500"/>
<br />

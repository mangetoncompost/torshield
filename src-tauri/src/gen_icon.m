#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>

int main(int argc, char *argv[]) {
    @autoreleasepool {
        NSString *symbolName = argc > 1 ? @(argv[1]) : @"shield.fill";
        NSString *outPath    = argc > 2 ? @(argv[2]) : @"/tmp/shield.png";
        CGFloat   size       = argc > 3 ? atof(argv[3]) : 18.0;

        NSImage *img = [NSImage imageWithSystemSymbolName:symbolName accessibilityDescription:nil];
        if (!img) { fprintf(stderr, "Symbol not found: %s\n", argv[1]); return 1; }

        NSImage *out = [[NSImage alloc] initWithSize:NSMakeSize(size, size)];
        [out lockFocus];
        [[NSColor whiteColor] set];
        [img drawInRect:NSMakeRect(0, 0, size, size)
               fromRect:NSZeroRect
              operation:NSCompositingOperationSourceOver
               fraction:1.0];
        [out unlockFocus];

        NSBitmapImageRep *rep = [NSBitmapImageRep imageRepWithData:[out TIFFRepresentation]];
        NSData *png = [rep representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
        [png writeToFile:outPath atomically:YES];
        printf("Written: %s\n", [outPath UTF8String]);
    }
    return 0;
}
